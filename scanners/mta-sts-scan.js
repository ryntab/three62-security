import dns from 'dns';
import https from 'https';

class MtaStsScanner {
  async scan(host) {
    const findings = [];
    let score = 100;

    // --------------------------------------------------------------------------
    // Extract base organizational domain (handles stripping www. cleanly)
    // --------------------------------------------------------------------------
    const cleanHost = host.replace(/\.$/, '').toLowerCase();
    const parts = cleanHost.split('.');

    // Fallback logic to get the root domain if someone passes a www subdomain
    let rootDomain = cleanHost;
    if (parts.length > 2 && parts[0] === 'www') {
      rootDomain = parts.slice(1).join('.');
    }

    // --------------------------------------------------------------------------
    // Helper: safe DNS TXT lookup
    // --------------------------------------------------------------------------
    const resolveTxt = (name) => {
      return new Promise((resolve) => {
        dns.resolveTxt(name, (err, records) => {
          if (err) return resolve([]);
          resolve(records.flat().filter(r => typeof r === 'string'));
        });
      });
    };

    // --------------------------------------------------------------------------
    // Helper: fetch a URL body over HTTPS
    // --------------------------------------------------------------------------
    const fetchText = (url, timeout = 5000) => {
      return new Promise((resolve) => {
        let isResolved = false;
        const safeResolve = (val) => { if (!isResolved) { isResolved = true; resolve(val); } };

        try {
          const req = https.get(url, { rejectUnauthorized: false, timeout }, (res) => {
            if (res.statusCode !== 200) return safeResolve(null);
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => {
              body += chunk;
              if (body.length > 4096) {
                res.destroy();
                safeResolve(body);
              }
            });
            res.on('end', () => safeResolve(body));
            res.on('error', () => safeResolve(null));
          });
          req.setTimeout(timeout, () => { req.destroy(); safeResolve(null); });
          req.on('error', () => safeResolve(null));
        } catch {
          safeResolve(null);
        }
      });
    };

    // --------------------------------------------------------------------------
    // Parse MTA-STS policy text into key/value pairs
    // --------------------------------------------------------------------------
    const parseMtaStsPolicy = (text) => {
      const policy = {};
      const mxHosts = [];
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
        const val = trimmed.slice(colonIdx + 1).trim();
        if (key === 'mx') {
          mxHosts.push(val);
        } else {
          policy[key] = val;
        }
      }
      policy.mx = mxHosts;
      return policy;
    };

    try {
      // ========================================================================
      // 1. MTA-STS DNS TXT Record — Checked against rootDomain
      // ========================================================================
      const mtaStsTxtRecords = await resolveTxt(`_mta-sts.${rootDomain}`);
      const mtaStsRecord = mtaStsTxtRecords.find(r => r.startsWith('v=STSv1'));

      if (!mtaStsRecord) {
        findings.push({
          severity: 'medium',
          category: 'mta-sts',
          title: 'MTA-STS Not Configured',
          description: 'No _mta-sts TXT record found. MTA-STS (RFC 8461) allows mail servers to declare that they support TLS, protecting email in transit from downgrade attacks and MitM interception.',
          recommendation: `Configure MTA-STS by: (1) Publishing a TXT record at _mta-sts.${rootDomain} with "v=STSv1; id=<timestamp>", (2) Hosting a policy file at https://mta-sts.${rootDomain}/.well-known/mta-sts.txt`
        });
        score -= 10;
      } else {
        // Parse the DNS record
        const idMatch = mtaStsRecord.match(/id=([^;]+)/);
        const policyId = idMatch?.[1]?.trim() || 'unknown';
        findings.push({
          severity: 'info',
          category: 'mta-sts',
          title: 'MTA-STS DNS Record Present',
          description: `MTA-STS is signalled via DNS. Record: "${mtaStsRecord}" | Policy ID: ${policyId}`,
          recommendation: 'No action required.'
        });

        // ======================================================================
        // 2. MTA-STS Policy File — Hardcoded strictly to mta-sts.<rootDomain>
        // ======================================================================
        const policyUrl = `https://mta-sts.${rootDomain}/.well-known/mta-sts.txt`;
        const policyBody = await fetchText(policyUrl);

        if (!policyBody) {
          findings.push({
            severity: 'high',
            category: 'mta-sts',
            title: 'MTA-STS Policy File Unreachable',
            description: `The DNS record for MTA-STS exists but the policy file at ${policyUrl} could not be fetched. Mail servers will treat this as a misconfiguration.`,
            recommendation: `Host a valid MTA-STS policy file at ${policyUrl}. Ensure the subdomain mta-sts.${rootDomain} resolves and serves HTTPS correctly.`
          });
          score -= 15;
        } else {
          const policy = parseMtaStsPolicy(policyBody);

          // Version check
          if (policy.version !== 'STSv1') {
            findings.push({
              severity: 'medium',
              category: 'mta-sts',
              title: 'MTA-STS Policy: Invalid Version',
              description: `Policy file version "${policy.version || 'missing'}" is not "STSv1".`,
              recommendation: 'Set the version field to "STSv1" in your MTA-STS policy file.'
            });
            score -= 5;
          }

          // Mode check
          const mode = policy.mode?.toLowerCase();
          if (!mode) {
            findings.push({
              severity: 'medium',
              category: 'mta-sts',
              title: 'MTA-STS Policy: Missing Mode',
              description: 'The MTA-STS policy file does not specify a mode.',
              recommendation: 'Set the "mode" field to "enforce", "testing", or "none".'
            });
            score -= 5;
          } else if (mode === 'none') {
            findings.push({
              severity: 'medium',
              category: 'mta-sts',
              title: 'MTA-STS Policy Mode: none',
              description: 'The MTA-STS policy is set to "mode: none", which disables enforcement. Inbound email is not protected from TLS downgrade attacks.',
              recommendation: 'Change the mode to "testing" to observe without enforcement, or "enforce" to fully protect inbound email.'
            });
            score -= 10;
          } else if (mode === 'testing') {
            findings.push({
              severity: 'low',
              category: 'mta-sts',
              title: 'MTA-STS Policy Mode: testing (Not Enforced)',
              description: 'MTA-STS is in "testing" mode. TLS is not yet enforced — this is suitable for initial validation but should be graduated to "enforce" mode.',
              recommendation: 'Monitor your TLS-RPT reports and upgrade to "mode: enforce" once you have confirmed all sending mail servers support TLS.'
            });
            score -= 5;
          } else if (mode === 'enforce') {
            findings.push({
              severity: 'info',
              category: 'mta-sts',
              title: 'MTA-STS Policy Mode: enforce ✓',
              description: `MTA-STS is fully enforced. All inbound SMTP connections must use TLS. MX hosts listed: ${policy.mx?.join(', ') || 'none specified'}.`,
              recommendation: 'No action required.'
            });
          }

          // max_age check
          const maxAge = parseInt(policy.max_age, 10);
          if (!isNaN(maxAge)) {
            if (maxAge < 86400) {
              findings.push({
                severity: 'low',
                category: 'mta-sts',
                title: 'MTA-STS Policy: max_age Too Short',
                description: `The max_age is set to ${maxAge} seconds (${(maxAge / 3600).toFixed(1)} hours). Very short cache durations reduce the effectiveness of MTA-STS.`,
                recommendation: 'Set max_age to at least 86400 (1 day). Recommended: 604800 (7 days) or 31557600 (1 year) in enforce mode.'
              });
            } else {
              findings.push({
                severity: 'info',
                category: 'mta-sts',
                title: 'MTA-STS Policy: max_age',
                description: `Policy cache duration: ${maxAge} seconds (${Math.round(maxAge / 86400)} days).`,
                recommendation: 'No action required.'
              });
            }
          }

          // MX host coverage check
          if (!policy.mx || policy.mx.length === 0) {
            findings.push({
              severity: 'medium',
              category: 'mta-sts',
              title: 'MTA-STS Policy: No MX Hosts Listed',
              description: 'The policy file does not list any allowed MX hostnames. All inbound connections may be rejected.',
              recommendation: 'Add mx: entries for each of your authoritative mail server hostnames.'
            });
            score -= 5;
          }
        }
      }

      // ========================================================================
      // 3. TLS-RPT Record — _smtp._tls.<rootDomain>
      // ========================================================================
      const tlsRptRecords = await resolveTxt(`_smtp._tls.${rootDomain}`);
      const tlsRptRecord = tlsRptRecords.find(r => r.startsWith('v=TLSRPTv1'));

      if (tlsRptRecord) {
        const ruaMatch = tlsRptRecord.match(/rua=([^;]+)/);
        findings.push({
          severity: 'info',
          category: 'mta-sts',
          title: 'TLS-RPT (SMTP TLS Reporting) Configured',
          description: `SMTP TLS reporting is enabled. Delivery failure reports will be sent to: ${ruaMatch?.[1] || 'address not parsed'}. Record: "${tlsRptRecord}"`,
          recommendation: 'No action required. Review TLS-RPT reports regularly.'
        });
      } else {
        findings.push({
          severity: 'info',
          category: 'mta-sts',
          title: 'TLS-RPT Not Configured',
          description: 'No _smtp._tls TXT record found. TLS-RPT (RFC 8460) allows mail servers to report TLS delivery failures to you.',
          recommendation: `Add a TXT record at _smtp._tls.${rootDomain}: "v=TLSRPTv1; rua=mailto:tls-reports@${rootDomain}"`
        });
      }

    } catch (err) {
      findings.push({
        severity: 'high',
        category: 'mta-sts',
        title: 'MTA-STS Scan Error',
        description: `Failed to complete MTA-STS scan: ${err.message}`,
        recommendation: 'Ensure DNS resolution is functional and the host is reachable.'
      });
      score = 0;
    }

    return {
      score: Math.max(0, score),
      findings
    };
  }
}

export default MtaStsScanner;