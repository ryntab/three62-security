import dns from 'dns';
import net from 'net';
import https from 'https';
import { promisify } from 'util';

const lookup = promisify(dns.lookup);
const resolve4 = promisify(dns.resolve4);
const resolvePtr = promisify(dns.resolvePtr);

class NetworkScanner {
  async scan(host) {
    const findings = [];
    let score = 100;

    // --------------------------------------------------------------------------
    // Helper: TCP ping — measures connect latency to port 80 or 443
    // (ICMP requires raw sockets; TCP connect is a reliable proxy)
    // --------------------------------------------------------------------------
    const tcpPing = (hostname, port = 443, timeout = 3000) => {
      return new Promise((resolve) => {
        const start = Date.now();
        const socket = new net.Socket();
        socket.setTimeout(timeout);

        socket.connect(port, hostname, () => {
          const latency = Date.now() - start;
          socket.destroy();
          resolve({ reachable: true, latency, port });
        });

        socket.on('timeout', () => { socket.destroy(); resolve({ reachable: false, latency: null, port }); });
        socket.on('error', () => {
          socket.destroy();
          // Try port 80 as fallback if 443 fails
          if (port === 443) {
            tcpPing(hostname, 80, timeout).then(resolve);
          } else {
            resolve({ reachable: false, latency: null, port });
          }
        });
      });
    };

    // --------------------------------------------------------------------------
    // Helper: DNS-based ASN lookup via Team Cymru
    // Reversed IP + .origin.asn.cymru.com → TXT with ASN info
    // --------------------------------------------------------------------------
    const lookupAsn = (ip) => {
      return new Promise((resolve) => {
        const reversed = ip.split('.').reverse().join('.');
        dns.resolveTxt(`${reversed}.origin.asn.cymru.com`, (err, records) => {
          if (err || !records || records.length === 0) return resolve(null);
          // Format: "ASN | IP-range | Country | Registry | Date"
          const raw = records.flat().join('');
          const parts = raw.split('|').map(p => p.trim());
          resolve({
            asn: parts[0] || null,
            ipRange: parts[1] || null,
            country: parts[2] || null,
            registry: parts[3] || null,
            allocated: parts[4] || null,
            raw
          });
        });
      });
    };

    // --------------------------------------------------------------------------
    // Helper: ASN name lookup via Team Cymru AS name service
    // --------------------------------------------------------------------------
    const lookupAsnName = (asn) => {
      return new Promise((resolve) => {
        if (!asn) return resolve(null);
        const cleanAsn = asn.replace(/^AS/i, '');
        dns.resolveTxt(`AS${cleanAsn}.asn.cymru.com`, (err, records) => {
          if (err || !records || records.length === 0) return resolve(null);
          const raw = records.flat().join('');
          const parts = raw.split('|').map(p => p.trim());
          resolve(parts[parts.length - 1] || null);
        });
      });
    };

    // --------------------------------------------------------------------------
    // Helper: RDAP lookup via ARIN for IP info
    // --------------------------------------------------------------------------
    const lookupArin = (ip) => {
      return new Promise((resolve) => {
        const url = `https://rdap.arin.net/registry/ip/${ip}`;
        let isResolved = false;
        const safeResolve = (val) => { if (!isResolved) { isResolved = true; resolve(val); } };

        try {
          const req = https.get(url, { timeout: 5000 }, (res) => {
            if (res.statusCode !== 200) return safeResolve(null);
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { body += chunk; if (body.length > 8192) { res.destroy(); safeResolve(body); } });
            res.on('end', () => {
              try {
                const data = JSON.parse(body);
                safeResolve({
                  name: data.name || null,
                  type: data.type || null,
                  handle: data.handle || null,
                  startAddress: data.startAddress || null,
                  endAddress: data.endAddress || null,
                  country: data.country || null,
                  org: data.entities?.[0]?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || null
                });
              } catch {
                safeResolve(null);
              }
            });
            res.on('error', () => safeResolve(null));
          });
          req.setTimeout(5000, () => { req.destroy(); safeResolve(null); });
          req.on('error', () => safeResolve(null));
        } catch {
          safeResolve(null);
        }
      });
    };

    try {
      // ========================================================================
      // 1. Resolve Primary IPv4 Address (Fixed using OS getaddrinfo layer)
      // ========================================================================
      let primaryIp = null;
      const cleanHost = host.toLowerCase();
      const parts = cleanHost.split('.');

      let rootDomain = cleanHost;
      if (parts.length > 2 && parts[0] === 'www') {
        rootDomain = parts.slice(1).join('.');
      }

      try {
        // Fix: Use lookup instead of resolve4 to cleanly evaluate CNAME proxies (Squarespace, Cloudflare, CDNs)
        const lookupResult = await lookup(cleanHost, { family: 4 });
        if (lookupResult && lookupResult.address) {
          primaryIp = lookupResult.address;
          findings.push({
            severity: 'info',
            category: 'network',
            title: `Resolved IP: ${primaryIp}`,
            description: `Primary IPv4 address for ${host}: ${primaryIp}`,
            recommendation: 'No action required.'
          });
        }
      } catch (err) {
        // Fallback: Check apex domain context using OS level resolution rules if primary node fails
        if (rootDomain !== cleanHost) {
          try {
            const fallbackResult = await lookup(rootDomain, { family: 4 });
            if (fallbackResult && fallbackResult.address) {
              primaryIp = fallbackResult.address;
              findings.push({
                severity: 'info',
                category: 'network',
                title: 'Subdomain Fallback Resolution Active',
                description: `Host ${host} has no explicit direct mapping. Traffic resolves through apex domain records context (${rootDomain}) pointing to IP: ${primaryIp}.`,
                recommendation: 'No mandatory action needed unless this subdomain requires dedicated routing parameters.'
              });
            }
          } catch (_) {
            // Both lookup attempts completely failed
          }
        }
      }

      // Safe early exit block if domain completely lacks structural lookup values
      if (!primaryIp) {
        findings.push({
          severity: 'high',
          category: 'network',
          title: 'Host Resolution Failed',
          description: `Unable to resolve ${host} or its root domain ${rootDomain} to an IP address.`,
          recommendation: 'Verify DNS A records are configured for this domain.'
        });
        score = 0;
        return { score, findings };
      }

      // ========================================================================
      // 2. Ping / TCP Reachability
      // ========================================================================
      const pingResult = await tcpPing(primaryIp);
      if (pingResult.reachable) {
        const latencyLabel =
          pingResult.latency < 50 ? 'Excellent' :
            pingResult.latency < 150 ? 'Good' :
              pingResult.latency < 300 ? 'Fair' : 'Poor';

        findings.push({
          severity: 'info',
          category: 'network',
          title: `Host Reachable — Latency: ${pingResult.latency}ms (${latencyLabel})`,
          description: `TCP connect to ${primaryIp}:${pingResult.port} succeeded in ${pingResult.latency}ms.`,
          recommendation: pingResult.latency >= 300
            ? 'High latency detected. Review server location, CDN configuration, or network routing.'
            : 'No action required.'
        });

        if (pingResult.latency >= 500) {
          findings.push({
            severity: 'low',
            category: 'network',
            title: 'High Server Latency',
            description: `Response latency of ${pingResult.latency}ms is above acceptable thresholds (>500ms). This can impact user experience and search ranking.`,
            recommendation: 'Consider a CDN, optimizing server-side response times, or migrating to a geographically closer data center.'
          });
          score -= 5;
        }
      } else {
        findings.push({
          severity: 'high',
          category: 'network',
          title: 'Host Unreachable (Ping Failed)',
          description: `TCP connection to ${primaryIp} on ports 443 and 80 both failed. The host may be down, behind a firewall that drops connections, or blocking probes.`,
          recommendation: 'Verify the server is online and that ports 80 and 443 are open to the internet.'
        });
        score -= 15;
      }

      // ========================================================================
      // 3. Reverse DNS (PTR) — Forward-Confirmed Check
      // ========================================================================
      try {
        const ptrRecords = await resolvePtr(primaryIp);
        if (ptrRecords.length > 0) {
          const ptrHostname = ptrRecords[0];
          let isFcrDns = false;
          try {
            const forwardIps = await resolve4(ptrHostname);
            isFcrDns = forwardIps.includes(primaryIp);
          } catch { /* forward lookup failed */ }

          if (isFcrDns) {
            findings.push({
              severity: 'info',
              category: 'network',
              title: 'Reverse DNS (FCrDNS): Pass',
              description: `${primaryIp} → ${ptrHostname} → ${primaryIp} (Forward-Confirmed rDNS verified).`,
              recommendation: 'No action required.'
            });
          } else {
            findings.push({
              severity: 'low',
              category: 'network',
              title: 'Reverse DNS: PTR Exists but FCrDNS Not Confirmed',
              description: `${primaryIp} has PTR record "${ptrHostname}" but the forward lookup of that hostname does not resolve back to ${primaryIp}. This can affect email deliverability.`,
              recommendation: 'Ensure the PTR record hostname has an A record pointing back to the same IP (Forward-Confirmed rDNS).'
            });
            score -= 5;
          }
        } else {
          findings.push({
            severity: 'medium',
            category: 'network',
            title: 'No Reverse DNS (PTR) Record',
            description: `No PTR record found for ${primaryIp}. Missing rDNS is a critical email deliverability factor — many mail servers will reject or penalize email from IPs without PTR records.`,
            recommendation: 'Contact your hosting provider or ISP and request a PTR record for your IP pointing to your mail server\'s fully qualified domain name.'
          });
          score -= 10;
        }
      } catch {
        findings.push({
          severity: 'info',
          category: 'network',
          title: 'Reverse DNS (PTR) Lookup Failed',
          description: `Unable to perform PTR lookup for ${primaryIp}.`,
          recommendation: 'Verify rDNS is configured with your hosting provider.'
        });
      }

      // ========================================================================
      // 4. ASN Lookup — Team Cymru DNS-based
      // ========================================================================
      const asnInfo = await lookupAsn(primaryIp);
      if (asnInfo) {
        const [asnName] = await Promise.all([lookupAsnName(asnInfo.asn)]);
        findings.push({
          severity: 'info',
          category: 'network',
          title: `ASN: ${asnInfo.asn}${asnName ? ` — ${asnName}` : ''}`,
          description: [
            `IP: ${primaryIp}`,
            `ASN: ${asnInfo.asn}`,
            asnName ? `Organization: ${asnName}` : null,
            `IP Range: ${asnInfo.ipRange}`,
            `Country: ${asnInfo.country}`,
            `Registry: ${asnInfo.registry}`,
            asnInfo.allocated ? `Allocated: ${asnInfo.allocated}` : null
          ].filter(Boolean).join(' | '),
          recommendation: 'No action required.'
        });

        const highAbuseKeywords = ['digitalocean', 'vultr', 'linode', 'ovh', 'hetzner', 'contabo'];
        if (asnName && highAbuseKeywords.some(k => asnName.toLowerCase().includes(k))) {
          findings.push({
            severity: 'info',
            category: 'network',
            title: 'Hosted on High-Volume VPS/Cloud Infrastructure',
            description: `This IP is registered to ${asnName}, a cloud/VPS provider with a large shared IP pool. Shared infrastructure can sometimes carry residual reputation issues from other tenants.`,
            recommendation: 'Monitor your IP reputation regularly. Consider dedicated IPs for mail sending if deliverability is a concern.'
          });
        }
      } else {
        findings.push({
          severity: 'info',
          category: 'network',
          title: 'ASN Lookup: No Data Returned',
          description: `Could not retrieve ASN information for ${primaryIp} via Team Cymru DNS.`,
          recommendation: 'No action required.'
        });
      }

      // ========================================================================
      // 5. ARIN RDAP Lookup
      // ========================================================================
      const arinInfo = await lookupArin(primaryIp);
      if (arinInfo) {
        findings.push({
          severity: 'info',
          category: 'network',
          title: `ARIN Whois: ${arinInfo.name || arinInfo.handle || 'Unknown Network'}`,
          description: [
            `Network: ${arinInfo.name || 'N/A'}`,
            `Handle: ${arinInfo.handle || 'N/A'}`,
            arinInfo.org ? `Organization: ${arinInfo.org}` : null,
            `Range: ${arinInfo.startAddress || 'N/A'} – ${arinInfo.endAddress || 'N/A'}`,
            arinInfo.country ? `Country: ${arinInfo.country}` : null
          ].filter(Boolean).join(' | '),
          recommendation: 'No action required.'
        });
      }

    } catch (err) {
      findings.push({
        severity: 'high',
        category: 'network',
        title: 'Network Scan Error',
        description: `Failed to complete network scan: ${err.message}`,
        recommendation: 'Check DNS resolution and network connectivity.'
      });
      score = 0;
    }

    return {
      score: Math.max(0, score),
      findings
    };
  }
}

export default NetworkScanner;