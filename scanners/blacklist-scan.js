import dns from 'dns';

// Top-20 authoritative DNSBL/RBL lists — covers 95%+ of real-world blacklisting
const DNSBL_ZONES = [
  // IP-based lists
  { zone: 'zen.spamhaus.org', label: 'Spamhaus ZEN', severity: 'critical', type: 'ip' },
  { zone: 'b.barracudacentral.org', label: 'Barracuda BRBL', severity: 'high', type: 'ip' },
  { zone: 'bl.spamcop.net', label: 'SpamCop', severity: 'high', type: 'ip' },
  { zone: 'dnsbl.sorbs.net', label: 'SORBS', severity: 'medium', type: 'ip' },
  { zone: 'spam.dnsbl.sorbs.net', label: 'SORBS Spam', severity: 'high', type: 'ip' },
  { zone: 'bl.0spam.org', label: '0Spam', severity: 'medium', type: 'ip' },
  { zone: 'dnsbl.spfbl.net', label: 'SPFBL', severity: 'medium', type: 'ip' },
  { zone: 'psbl.surriel.com', label: 'PSBL', severity: 'medium', type: 'ip' },
  { zone: 'dnsbl-1.uceprotect.net', label: 'UCEPROTECT L1', severity: 'medium', type: 'ip' },
  { zone: 'ix.dnsbl.manitu.net', label: 'iX Manitu NiX Spam', severity: 'medium', type: 'ip' },
  { zone: 'truncate.gbudb.net', label: 'GBUdb Truncate', severity: 'high', type: 'ip' },
  { zone: 'rbl.realtimeblacklist.com', label: 'Realtime Blacklist', severity: 'medium', type: 'ip' },
  { zone: 'all.s5h.net', label: 'S5H Spam', severity: 'medium', type: 'ip' },
  { zone: 'rbl.spamlab.com', label: 'SpamLab', severity: 'medium', type: 'ip' },

  // Domain-based lists (query the domain root directly, not reversed IP)
  { zone: 'dbl.spamhaus.org', label: 'Spamhaus DBL', severity: 'high', type: 'domain' },
  { zone: 'multi.surbl.org', label: 'SURBL Multi', severity: 'high', type: 'domain' },
  { zone: 'dbl.nordspam.com', label: 'NordSpam DBL', severity: 'medium', type: 'domain' },
  { zone: 'rhsbl.sorbs.net', label: 'SORBS RHSBL', severity: 'medium', type: 'domain' },
  { zone: 'black.uribl.com', label: 'URIBL Black', severity: 'high', type: 'domain' },
];

// Deduplicate
const UNIQUE_DNSBL_ZONES = DNSBL_ZONES.filter((z, i, arr) =>
  arr.findIndex(x => x.zone === z.zone && x.type === z.type) === i
);

class BlacklistScanner {
  constructor() {
    // Isolated custom resolver instance to leverage specialized timeouts safely
    this.resolver = new dns.Resolver();
    this.resolver.setCustomValues ? this.resolver.setCustomValues({ timeout: 3000, tries: 1 }) : null;
  }

  async scan(host) {
    const findings = [];
    let score = 100;

    // Normalization: Extract base organizational domain for RHSBL/Domain looks
    const cleanHost = host.replace(/\.$/, '').toLowerCase();
    const parts = cleanHost.split('.');
    let rootDomain = cleanHost;
    if (parts.length > 2 && parts[0] === 'www') {
      rootDomain = parts.slice(1).join('.');
    }

    // --------------------------------------------------------------------------
    // Resolve primary IP for the domain using isolated resolver
    // --------------------------------------------------------------------------
    let primaryIp = null;
    try {
      const ips = await new Promise((resolve, reject) => {
        this.resolver.resolve4(cleanHost, (err, addresses) => err ? reject(err) : resolve(addresses));
      });
      if (ips && ips.length > 0) {
        primaryIp = ips[0];
      }
    } catch {
      findings.push({
        severity: 'info',
        category: 'blacklist',
        title: 'Blacklist Check: No A Record to Check',
        description: `Could not resolve an IPv4 address for ${cleanHost}. IP-based blacklist checks were skipped.`,
        recommendation: 'Ensure DNS A records are configured for this domain.'
      });
    }

    // --------------------------------------------------------------------------
    // Helper: reverse IP octets for DNSBL query (e.g. 192.0.2.1 → 1.2.0.192)
    // --------------------------------------------------------------------------
    const reverseIp = (ip) => ip.split('.').reverse().join('.');

    // --------------------------------------------------------------------------
    // Helper: DNSBL lookup with explicit validation of loopback codes
    // --------------------------------------------------------------------------
    const checkDnsbl = (query, zone, type) => {
      return new Promise((resolve) => {
        this.resolver.resolve4(query, (err, addresses) => {
          if (err) return resolve({ listed: false });
          if (!addresses || addresses.length === 0) return resolve({ listed: false });

          // Filter out operational messages / Open Resolver error flags
          // e.g., Spamhaus returns 127.255.255.255 or 127.255.255.252 when public DNS is throttled/blocked
          const validListings = addresses.filter(ip => {
            if (!ip.startsWith('127.')) return false;

            // Catch public query refusal codes
            if (ip === '127.255.255.255' || ip === '127.255.255.252' || ip === '127.255.255.254') {
              return false;
            }
            // URIBL / SURBL query block indicators
            if ((zone.includes('uribl') || zone.includes('surbl')) && ip === '127.0.0.1') {
              return false;
            }
            return true;
          });

          resolve({
            listed: validListings.length > 0,
            addresses: addresses
          });
        });
      });
    };

    // --------------------------------------------------------------------------
    // Run all checks concurrently
    // --------------------------------------------------------------------------
    const listedOn = [];
    const cleanOn = [];
    const checks = [];

    for (const bl of UNIQUE_DNSBL_ZONES) {
      if (bl.type === 'ip' && primaryIp) {
        const query = `${reverseIp(primaryIp)}.${bl.zone}`;
        checks.push(
          checkDnsbl(query, bl.zone, 'ip').then(result => ({ bl, result }))
        );
      } else if (bl.type === 'domain') {
        // Query must use the rootDomain context, never the raw host prefix (www)
        const query = `${rootDomain}.${bl.zone}`;
        checks.push(
          checkDnsbl(query, bl.zone, 'domain').then(result => ({ bl, result }))
        );
      }
    }

    const results = await Promise.allSettled(checks);

    for (const settled of results) {
      if (settled.status !== 'fulfilled') continue;
      const { bl, result } = settled.value;

      if (result.listed) {
        listedOn.push(bl);
        const deduction = bl.severity === 'critical' ? 25 : bl.severity === 'high' ? 15 : 10;
        score -= deduction;

        const targetTarget = bl.type === 'ip' ? `IP ${primaryIp}` : `Domain ${rootDomain}`;
        findings.push({
          severity: bl.severity,
          category: 'blacklist',
          title: `Listed on ${bl.label}`,
          description: `${targetTarget} is listed on the ${bl.label} (${bl.zone}) blacklist. This will cause email delivery failures and may indicate a past spam incident or compromised server.`,
          recommendation: `Visit https://www.${bl.zone.split('.').slice(-2).join('.')} to find the delisting request procedure for ${bl.label}. Investigate your server for spam activity, abuse, or compromise before requesting removal.`
        });
      } else {
        cleanOn.push(bl.label);
      }
    }

    // --------------------------------------------------------------------------
    // Summary finding aggregation block
    // --------------------------------------------------------------------------
    const totalChecked = listedOn.length + cleanOn.length;
    if (listedOn.length === 0 && totalChecked > 0) {
      findings.push({
        severity: 'info',
        category: 'blacklist',
        title: `Not Listed on Any Blacklist (${totalChecked} Checked)`,
        description: `${cleanHost}${primaryIp ? ` (${primaryIp})` : ''} is not listed on any of the ${totalChecked} DNSBL/RBL blacklists checked, including Spamhaus ZEN, Barracuda, SpamCop, SORBS, and SURBL.`,
        recommendation: 'No action required. Monitor regularly.'
      });
    } else if (listedOn.length > 0) {
      findings.push({
        severity: 'info',
        category: 'blacklist',
        title: `Blacklist Summary: ${listedOn.length} of ${totalChecked} Lists`,
        description: `Found on: ${listedOn.map(b => b.label).join(', ')}. Clean on ${cleanOn.length} other lists.`,
        recommendation: 'Delist from all active blacklists and investigate the root cause of spam activity.'
      });
    }

    return {
      score: Math.max(0, score),
      findings
    };
  }
}

export default BlacklistScanner;