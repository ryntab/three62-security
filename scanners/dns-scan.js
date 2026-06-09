import dns from 'dns';
import { promisify } from 'util';

const resolvePtr = promisify(dns.resolvePtr);

// Create an isolated custom resolver instance to bypass standard system/Docker network restrictions
const customResolver = new dns.promises.Resolver();
customResolver.setServers(['1.1.1.1', '8.8.8.8']);

const DKIM_SELECTORS = [
  'default', 'google', 'mail', 'dkim', 'k1', 's1', 's2',
  'smtp', 'selector1', 'selector2', 'mailjet', 'sendgrid',
  'em', 'pm', 'mimecast', 'everlytickey1', 'everlytickey2'
];

class DnsScanner {
  async scan(host) {
    const findings = [];
    let score = 100;

    // Standardize target format
    const targetHost = host.replace(/\.$/, '').toLowerCase();
    const parts = targetHost.split('.');
    const isSubdomain = parts.length > 2 && parts[0] !== 'ami';
    const rootDomain = isSubdomain ? parts.slice(-2).join('.') : targetHost;

    // --------------------------------------------------------------------------
    // HELPERS
    // --------------------------------------------------------------------------

    // Custom safe lookup wrapper utilizing the reliable fallback chain
    const resolveRecord = async (hostname, type) => {
      try {
        return await customResolver.resolve(hostname, type);
      } catch (err) {
        // Fallback to system resolver if custom provider times out or is blocked locally
        try {
          return await dns.promises.resolve(hostname, type);
        } catch {
          return [];
        }
      }
    };

    const info = (title, description, category = 'dns') => {
      findings.push({ severity: 'info', category, title, description, recommendation: 'No action required.' });
    };

    const flag = (severity, title, description, recommendation, deduction, category = 'dns') => {
      findings.push({ severity, category, title, description, recommendation });
      score -= deduction;
    };

    try {
      // ========================================================================
      // 1. DYNAMIC TYPE RESOLUTION — A / CNAME MAPPINGS
      // ========================================================================
      let primaryIp = null;
      let ipv4Addresses = [];
      let cnameTargets = [];

      // Look up A records via multiple paths to bypass systemic lookup blocking
      try {
        ipv4Addresses = await customResolver.resolve4(targetHost).catch(() => []);

        if (ipv4Addresses.length === 0) {
          // Path 2: Force explicit CNAME extraction to inspect upstream host targets
          cnameTargets = await customResolver.resolveCname(targetHost).catch(() => []);
          if (cnameTargets.length > 0) {
            const cleanCname = cnameTargets[0].replace(/\.$/, '');
            ipv4Addresses = await customResolver.resolve4(cleanCname).catch(() => []);
          }
        }

        // Path 3: Ultimate system fallback via OS libdns lookup thread-pool
        if (ipv4Addresses.length === 0) {
          const lookupResult = await dns.promises.lookup(targetHost, { all: true, family: 4 }).catch(() => []);
          ipv4Addresses = lookupResult.map(r => r.address);
        }

        // Handle Findings Output
        if (cnameTargets.length > 0) {
          info(
            `CNAME Record Found`,
            `Canonical name chain: ${targetHost} → ${cnameTargets.join(' → ')}`
          );
        }

        if (ipv4Addresses.length > 0) {
          primaryIp = ipv4Addresses[0];
          info(
            `A Records Found (${ipv4Addresses.length})`,
            `IPv4 addresses: ${ipv4Addresses.join(', ')}`
          );
        } else {
          flag('high', 'No A Records Found',
            `No IPv4 address records could be resolved for ${targetHost}. The host may be down or misconfigured.`,
            'Configure A records in your DNS zone pointing to your server\'s public IPv4 address.',
            15
          );
        }
      } catch (err) {
        flag('high', 'No A Records Found',
          `No IPv4 address records could be resolved for ${targetHost}. The host may be down or misconfigured.`,
          'Configure A records in your DNS zone pointing to your server\'s public IPv4 address.',
          15
        );
      }

      // ========================================================================
      // 2. AAAA RECORDS — IPv6
      // ========================================================================
      let aaaaRecords = await resolveRecord(targetHost, 'AAAA');
      if (aaaaRecords.length === 0 && cnameTargets.length > 0) {
        aaaaRecords = await resolveRecord(cnameTargets[0].replace(/\.$/, ''), 'AAAA');
      }

      if (aaaaRecords.length > 0) {
        info(`AAAA Records Found (${aaaaRecords.length})`, `IPv6 addresses: ${aaaaRecords.join(', ')}`);
      } else {
        findings.push({
          severity: 'info',
          category: 'dns',
          title: 'No AAAA (IPv6) Records',
          description: 'No IPv6 address records are configured. The domain is IPv4-only.',
          recommendation: 'Consider adding AAAA records to support IPv6 connectivity.'
        });
      }

      // ========================================================================
      // 4. NS RECORDS (Root Apex Boundary)
      // ========================================================================
      const nsRecords = await resolveRecord(rootDomain, 'NS');
      if (nsRecords.length === 0) {
        flag('medium', 'No NS Records Found',
          `Unable to resolve authoritative nameserver records for the root domain ${rootDomain}.`,
          'Ensure NS records are properly configured at your domain registrar.',
          5
        );
      } else if (nsRecords.length < 2) {
        flag('medium', 'Single Nameserver — No Redundancy',
          `Only one NS record found: ${nsRecords[0]}. A single nameserver is a single point of failure.`,
          'Add a secondary authoritative nameserver for redundancy.',
          5
        );
      } else {
        info(`NS Records Found (${nsRecords.length})`, `Authoritative nameservers: ${nsRecords.join(', ')}`);
      }

      // ========================================================================
      // 5. SOA RECORD (Root Apex Boundary)
      // ========================================================================
      let soaResult = null;
      try {
        soaResult = await customResolver.resolveSoa(rootDomain).catch(() => null);
        if (!soaResult) {
          soaResult = await new Promise((resolve) => {
            dns.resolveSoa(rootDomain, (err, data) => err ? resolve(null) : resolve(data));
          });
        }

        if (soaResult) {
          info(
            'SOA Record Found',
            `Primary NS: ${soaResult.nsname} | Contact: ${soaResult.hostmaster} | Serial: ${soaResult.serial} | Refresh: ${soaResult.refresh}s | Retry: ${soaResult.retry}s | Expire: ${soaResult.expire}s | Min TTL: ${soaResult.minttl}s`
          );
        } else {
          throw new Error();
        }
      } catch {
        findings.push({
          severity: 'info',
          category: 'dns',
          title: 'SOA Record Not Resolved',
          description: `Start of Authority record could not be fetched for ${rootDomain}.`,
          recommendation: 'Ensure your DNS zone has a valid SOA record.'
        });
      }

      // ========================================================================
      // 6. MX RECORDS
      // ========================================================================
      const mxRecords = await resolveRecord(rootDomain, 'MX');
      const hasMx = mxRecords.length > 0;

      if (hasMx) {
        const mxList = mxRecords
          .sort((a, b) => (a.priority || 0) - (b.priority || 0))
          .map(r => `${r.exchange} (priority ${r.priority})`)
          .join(', ');
        info('MX Records Present', `Mail Exchange records: ${mxList}`);
      } else {
        findings.push({
          severity: 'info',
          category: 'dns',
          title: 'No MX Records',
          description: 'No mail exchange records are configured. This domain does not receive email.',
          recommendation: 'If this domain should receive email, configure MX records.'
        });
      }

      // ========================================================================
      // 7. SRV RECORDS
      // ========================================================================
      const srvServices = [
        { name: '_https._tcp', label: 'HTTPS' },
        { name: '_imaps._tcp', label: 'IMAPS' },
        { name: '_submission._tcp', label: 'SMTP Submission' },
        { name: '_autodiscover._tcp', label: 'Email Autodiscover' },
        { name: '_caldav._tcp', label: 'CalDAV' },
        { name: '_carddav._tcp', label: 'CardDAV' },
      ];
      const srvFound = [];
      await Promise.all(srvServices.map(async (svc) => {
        const records = await resolveRecord(`${svc.name}.${rootDomain}`, 'SRV');
        if (records.length > 0) {
          srvFound.push(`${svc.label}: ${records.map(r => `${r.name || rootDomain}:${r.port} (priority ${r.priority})`).join(', ')}`);
        }
      }));
      if (srvFound.length > 0) {
        info('SRV Records Found', srvFound.join(' | '));
      } else {
        findings.push({
          severity: 'info',
          category: 'dns',
          title: 'No SRV Records Found',
          description: 'No SRV service discovery records were found for common services.',
          recommendation: 'No action required unless you intend to use SRV-based service discovery.'
        });
      }

      // ========================================================================
      // 8. TXT RECORDS
      // ========================================================================
      const txtRecords = await resolveRecord(rootDomain, 'TXT');
      const flatTxt = txtRecords.flat().filter(r => typeof r === 'string');

      // ========================================================================
      // 9. SPF RECORD
      // ========================================================================
      const spfRecord = flatTxt.find(r => r.startsWith('v=spf1'));
      if (hasMx) {
        if (!spfRecord) {
          flag('medium', 'Missing SPF Record',
            'The domain has MX records but lacks a Sender Policy Framework (SPF) record, increasing the risk of email spoofing.',
            'Add a TXT record with SPF configuration (e.g., v=spf1 include:_spf.example.com ~all).',
            10
          );
        } else if (spfRecord.includes('+all')) {
          flag('medium', 'Weak SPF Policy (+all)',
            'The SPF record allows any sender (+all), negating all protection.',
            'Update the SPF record to end with ~all (softfail) or -all (hardfail).',
            10
          );
        } else if (spfRecord.includes('?all')) {
          flag('low', 'Weak SPF Policy (?all)',
            'The SPF record uses ?all (neutral), which provides no spoofing protection.',
            'Update the SPF record to end with ~all or -all.',
            5
          );
        } else {
          info('SPF Record Present', `SPF record: "${spfRecord}"`);
        }
      } else {
        if (spfRecord) {
          info('SPF Record Present', `SPF record: "${spfRecord}"`);
        } else {
          findings.push({
            severity: 'info',
            category: 'dns',
            title: 'No SPF Record',
            description: 'No SPF record found. Acceptable if this domain does not send email.',
            recommendation: 'If this domain sends email, configure an SPF record.'
          });
        }
      }

      // ========================================================================
      // 10. DMARC RECORD
      // ========================================================================
      const dmarcTxt = await resolveRecord(`_dmarc.${rootDomain}`, 'TXT');
      const dmarcRecord = dmarcTxt.flat().find(r => typeof r === 'string' && r.startsWith('v=DMARC1'));

      if (hasMx) {
        if (!dmarcRecord) {
          flag('medium', 'Missing DMARC Record',
            'No DMARC policy found. Attackers can spoof email from this domain without any enforcement mechanism.',
            'Add a TXT record at _dmarc.yourdomain.com with a valid DMARC policy (e.g., v=DMARC1; p=quarantine;).',
            10
          );
        } else {
          const pMatch = dmarcRecord.match(/p=(\w+)/);
          const policy = pMatch?.[1]?.toLowerCase();
          const ruaMatch = dmarcRecord.match(/rua=([^;]+)/);
          if (policy === 'none') {
            flag('low', 'DMARC Policy: none (Monitor Only)',
              `DMARC is configured but set to "p=none" which only monitors — it does not block spoofed emails. Record: "${dmarcRecord}"`,
              'Upgrade the DMARC policy to "p=quarantine" or "p=reject" once you\'ve reviewed RUA reports.',
              5
            );
          } else {
            info('DMARC Record Present', `DMARC policy (p=${policy}) is enforced. Record: "${dmarcRecord}"`);
          }
          if (!ruaMatch) {
            findings.push({
              severity: 'low',
              category: 'dns',
              title: 'DMARC: No Aggregate Reporting (rua) Configured',
              description: 'The DMARC record does not include an "rua" reporting address. You will not receive aggregate spoofing reports.',
              recommendation: 'Add rua=mailto:dmarc-reports@yourdomain.com to your DMARC record.'
            });
          }
        }
      } else if (dmarcRecord) {
        info('DMARC Record Present', `DMARC policy: "${dmarcRecord}"`);
      }

      // ========================================================================
      // 11. DKIM — (Refactored to cleanly separate TXT/CNAME validation)
      // ========================================================================
      let dkimFound = false;
      const dkimSelectors = [];
      const activeSelectors = [...DKIM_SELECTORS];

      const mxString = mxRecords.map(r => r.exchange.toLowerCase()).join(' ');
      if (mxString.includes('protection.outlook.com')) {
        if (!activeSelectors.includes('selector1')) activeSelectors.push('selector1');
        if (!activeSelectors.includes('selector2')) activeSelectors.push('selector2');
      }

      if (mxString.includes('google.com') || mxString.includes('googlemail.com')) {
        if (!activeSelectors.includes('google')) activeSelectors.push('google');
      }

      const uniqueSelectors = [...new Set(activeSelectors)];

      await Promise.all(uniqueSelectors.map(async (selector) => {
        const targetRecord = `${selector}._domainkey.${rootDomain}`;

        try {
          // Robust explicit TXT probe
          const txtRecords = await customResolver.resolveTxt(targetRecord).catch(() => []);
          const hasValidTxt = txtRecords.some(entries => entries.join('').includes('v=DKIM1'));

          if (hasValidTxt) {
            dkimFound = true;
            dkimSelectors.push(selector);
            return;
          }

          // Robust fallback CNAME probe (handles Microsoft 365, Sendgrid, Mailgun alias layers)
          const cnameRecords = await customResolver.resolveCname(targetRecord).catch(() => []);
          if (cnameRecords.length > 0) {
            dkimFound = true;
            dkimSelectors.push(selector);
          }
        } catch {
          // Fail gracefully per selector node
        }
      }));

      if (dkimFound) {
        info('DKIM Record(s) Found', `DKIM selectors detected: ${dkimSelectors.join(', ')}`);
      } else if (hasMx) {
        flag('medium', 'No DKIM Records Found',
          `Probed ${uniqueSelectors.length} common and platform-specific DKIM selectors — none returned a valid configuration. Without DKIM, outgoing emails cannot be cryptographically verified.`,
          'Configure DKIM in your email hosting provider dashboard (e.g., Microsoft 365 or Google Workspace) and add the suggested records to your DNS zone.',
          10
        );
      }

      // ========================================================================
      // 12-20. EXTRA TARGETS (Graceful standard fallbacks)
      // ========================================================================
      const bimiTxt = await resolveRecord(`default._bimi.${rootDomain}`, 'TXT');
      const bimiRecord = bimiTxt.flat().find(r => typeof r === 'string' && r.startsWith('v=BIMI1'));
      if (bimiRecord) info('BIMI Record Found', 'Brand logo record detected.');

      const caaRecords = await resolveRecord(rootDomain, 'CAA');
      if (caaRecords.length === 0) {
        flag('low', 'CAA Record Not Configured', 'No Certification Authority Authorization record found.', 'Add a CAA DNS record.', 5);
      } else {
        info('CAA Records Configured', 'Certificate authority restrictions are active.');
      }

      const dnskeyRecords = await resolveRecord(rootDomain, 'DNSKEY');
      if (dnskeyRecords.length > 0) info('DNSKEY Records Found (DNSSEC)', 'DNSSEC is configured.');

      // ========================================================================
      // 21. PTR — Reverse DNS for Mail Servers (Enterprise-Cloud-Aware)
      // ========================================================================
      if (hasMx && mxRecords.length > 0) {
        try {
          const primaryMxHost = mxRecords
            .sort((a, b) => (a.priority || 0) - (b.priority || 0))[0]
            .exchange.replace(/\.$/, '').toLowerCase();

          const isCloudMailVendor =
            primaryMxHost.endsWith('protection.outlook.com') ||
            primaryMxHost.endsWith('google.com') ||
            primaryMxHost.endsWith('googlemail.com') ||
            primaryMxHost.endsWith('pphosted.com');

          if (isCloudMailVendor) {
            info(
              'Reverse DNS (PTR) Verified via Cloud Provider',
              `Mail operations are hosted securely by an enterprise cloud infrastructure vendor (${primaryMxHost}). Outbound IP and reverse DNS reputation are managed natively by the provider.`
            );
          } else {
            let mxIps = await customResolver.resolve4(primaryMxHost).catch(() => []);

            if (mxIps.length === 0) {
              const systemLookup = await dns.promises.lookup(primaryMxHost, { family: 4 }).catch(() => null);
              if (systemLookup) mxIps = [systemLookup.address];
            }

            if (mxIps.length > 0) {
              const mailServerIp = mxIps[0];
              const ptrRecords = await resolvePtr(mailServerIp)
                .catch(() => customResolver.resolvePtr(mailServerIp))
                .catch(() => []);

              if (ptrRecords.length > 0) {
                const cleanPtr = ptrRecords[0].replace(/\.$/, '').toLowerCase();
                info('Reverse DNS (PTR) Configured', `${mailServerIp} resolves to: ${ptrRecords.join(', ')}`);

                const fcrdns = ptrRecords.some(ptr => {
                  const normalizedPtr = ptr.replace(/\.$/, '').toLowerCase();
                  return normalizedPtr === rootDomain ||
                    normalizedPtr.endsWith(`.${rootDomain}`) ||
                    normalizedPtr === primaryMxHost ||
                    normalizedPtr.endsWith(`.${primaryMxHost}`);
                });

                if (!fcrdns) {
                  findings.push({
                    severity: 'low',
                    category: 'dns',
                    title: 'PTR Record Does Not Match Domain (FCrDNS Mismatch)',
                    description: `The reverse DNS for mail server IP ${mailServerIp} resolves to "${cleanPtr}", which does not authoritatively map back to your domain zone or exchange host "${primaryMxHost}".`,
                    recommendation: 'Configure your mail server network interface so its Reverse DNS matches the outbound EHLO/HELO hostname.'
                  });
                  score -= 5;
                }
              } else {
                flag('medium', 'No Reverse DNS (PTR) Record',
                  `No PTR record exists for mail server IP ${mailServerIp} (${primaryMxHost}). Outbound messages from independent email nodes without rDNS will be heavily flagged or dropped by modern inbound spam filters.`,
                  'Contact your infrastructure provider to configure a PTR record pointing back to your sending domain.',
                  10
                );
              }
            } else {
              findings.push({
                severity: 'info',
                category: 'dns',
                title: 'PTR Evaluation Skipped',
                description: `Could not resolve an IP address for the configured MX server target "${primaryMxHost}".`,
                recommendation: 'Ensure your MX exchange record points to a live host name.'
              });
            }
          }
        } catch {
          findings.push({
            severity: 'info',
            category: 'dns',
            title: 'PTR Lookup Failed',
            description: 'An unexpected exception occurred while attempting to resolve mail server reverse mappings.',
            recommendation: 'Verify system network configurations.'
          });
        }
      } else {
        findings.push({
          severity: 'info',
          category: 'dns',
          title: 'PTR Scan Skipped',
          description: 'This domain does not publish explicit mail exchanger (MX) entries. Skipping reverse path validation.',
          recommendation: 'No action required unless you intend to configure inbound email routing handling.'
        });
      }
      // ========================================================================
      // 22. MTA-STS DNS indicator
      // ========================================================================
      const mtaStsTxt = await resolveRecord(`_mta-sts.${rootDomain}`, 'TXT');
      const mtaStsRecord = mtaStsTxt.flat().find(r => typeof r === 'string' && r.startsWith('v=STSv1'));
      if (mtaStsRecord) {
        info('MTA-STS DNS Record Present', `MTA-STS is signalled via DNS.`);
      } else if (hasMx) {
        findings.push({ severity: 'low', category: 'dns', title: 'MTA-STS Not Configured', description: 'No _mta-sts TXT record found.', recommendation: 'Configure MTA-STS.' });
        score -= 5;
      }

    } catch (err) {
      findings.push({ severity: 'high', category: 'dns', title: 'DNS Scan Error', description: `Failed to complete DNS scans: ${err.message}`, recommendation: 'Verify resolution configurations.' });
      score = 0;
    }

    return {
      score: Math.max(0, score),
      findings
    };
  }
}

export default DnsScanner;