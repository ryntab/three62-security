import tls from 'tls';
import https from 'https';

class TlsScanner {
  async scan(host) {
    const findings = [];
    let score = 100;

    // Default meta structure to return even on complete failure
    let meta = {
      protocol: null,
      cipher: null,
      issuer: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      sans: []
    };

    // Default simple summary structure
    let summary = {
      ssl_valid: false,
      expiration: null,
      issuer: null
    };

    const probeTls = (hostname) => {
      return new Promise((resolve) => {
        const socket = tls.connect(
          {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false // We want to inspect even invalid certs
          },
          () => {
            const cert = socket.getPeerCertificate(true);
            const cipher = socket.getCipher();
            const protocol = socket.getProtocol();
            const authorized = socket.authorized;
            const authError = socket.authorizationError;

            socket.end();
            resolve({
              success: true,
              cert,
              cipher,
              protocol,
              authorized,
              authError
            });
          }
        );

        socket.setTimeout(4000);

        socket.on('timeout', () => {
          socket.destroy();
          resolve({ success: false, error: 'Connection timeout' });
        });

        socket.on('error', (err) => {
          socket.destroy();
          resolve({ success: false, error: err.message });
        });
      });
    };

    const checkProtocolSupport = (hostname, protocol) => {
      return new Promise((resolve) => {
        const socket = tls.connect(
          {
            host: hostname,
            port: 443,
            servername: hostname,
            minVersion: protocol,
            maxVersion: protocol,
            rejectUnauthorized: false
          },
          () => {
            socket.end();
            resolve(true);
          }
        );
        socket.setTimeout(2500);
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
      });
    };

    try {
      const [result, hasTls13, hasTls12] = await Promise.all([
        probeTls(host),
        checkProtocolSupport(host, 'TLSv1.3'),
        checkProtocolSupport(host, 'TLSv1.2')
      ]);

      if (!result.success) {
        findings.push({
          severity: 'high',
          category: 'tls',
          title: 'TLS/SSL Service Unavailable',
          description: `Failed to connect via TLS on port 443: ${result.error}`,
          recommendation: 'Enable HTTPS (TLS/SSL) on port 443 to secure user communications.'
        });
        return { score: 0, findings, meta, summary };
      }

      const { cert, cipher, protocol, authorized, authError } = result;

      if (!cert || Object.keys(cert).length === 0) {
        findings.push({
          severity: 'high',
          category: 'tls',
          title: 'No SSL/TLS Certificate Returned',
          description: 'The server completed the TLS handshake but did not present a valid certificate.',
          recommendation: 'Install a valid SSL/TLS certificate.'
        });
        return { score: 0, findings, meta, summary };
      }

      // --- POPULATE METADATA & SUMMARY ---
      const validTo = new Date(cert.valid_to);
      const validFrom = new Date(cert.valid_from);
      const now = new Date();
      const diffMs = validTo - now;
      const calculatedDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

      let parsedSans = [];
      if (cert.subjectaltname) {
        parsedSans = cert.subjectaltname
          .split(',')
          .map(item => item.replace(/^DNS:/i, '').trim())
          .filter(Boolean);
      }

      const resolvedIssuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown CA';

      meta = {
        protocol,
        cipher: cipher ? `${cipher.name} (${cipher.bits} bits)` : null,
        issuer: resolvedIssuer,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining: calculatedDays,
        sans: parsedSans
      };

      // Base validation tracking for the summary layer
      const isExpired = now > validTo;
      const isHostMismatch = authError && authError.includes('Host name mismatch');

      summary = {
        ssl_valid: authorized && !isExpired && !isHostMismatch,
        expiration: cert.valid_to,
        issuer: resolvedIssuer
      };
      // ------------------------------------

      // Protocol support wins
      if (hasTls13) {
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'TLS 1.3 Supported',
          description: 'The server supports TLS 1.3, the latest and most secure version of the TLS protocol.',
          recommendation: 'No action required.'
        });
      }
      if (hasTls12) {
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'TLS 1.2 Supported',
          description: 'The server supports TLS 1.2, which is widely compatible and secure.',
          recommendation: 'No action required.'
        });
      }

      // 1. Certificate Validation Chain
      if (!authorized) {
        findings.push({
          severity: 'high',
          category: 'tls',
          title: 'Untrusted SSL/TLS Certificate',
          description: `The certificate is untrusted. Validation error: ${authError || 'unknown validation failure'}.`,
          recommendation: 'Install a certificate issued by a trusted public Certificate Authority (CA) such as Let\'s Encrypt.'
        });
        score -= 15;
      } else {
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'Certificate Valid',
          description: 'The SSL/TLS certificate is valid and trusted by public authorities.',
          recommendation: 'No action required.'
        });
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'Trusted Issuer',
          description: `The certificate was issued by a trusted certificate authority: ${meta.issuer}.`,
          recommendation: 'No action required.'
        });
      }

      // 2. Hostname matching
      if (isHostMismatch) {
        findings.push({
          severity: 'high',
          category: 'tls',
          title: 'Certificate Hostname Mismatch',
          description: `The certificate name does not match the requested hostname: "${host}".`,
          recommendation: 'Ensure your TLS certificate includes the correct Common Name (CN) or Subject Alternative Name (SAN) for this domain.'
        });
        score -= 15;
      }

      // 3. Expiration checks
      if (isExpired) {
        findings.push({
          severity: 'high',
          category: 'tls',
          title: 'Expired SSL/TLS Certificate',
          description: `The certificate expired on ${cert.valid_to}.`,
          recommendation: 'Renew the SSL/TLS certificate immediately.'
        });
        score -= 15;
      } else {
        if (calculatedDays > 0) {
          findings.push({
            severity: 'info',
            category: 'tls',
            title: `Certificate Expires In ${calculatedDays} Days`,
            description: `The certificate is valid until ${cert.valid_to} (${calculatedDays} days remaining).`,
            recommendation: 'No action required.'
          });

          if (calculatedDays < 30) {
            findings.push({
              severity: calculatedDays < 15 ? 'high' : 'medium',
              category: 'tls',
              title: `Certificate expires within ${calculatedDays < 15 ? '15' : '30'} days`,
              description: `The certificate will expire on ${cert.valid_to} (${calculatedDays} days left).`,
              recommendation: 'Renew the certificate before it expires to prevent service disruption.'
            });
            score -= (calculatedDays < 15 ? 15 : 10);
          }
        }
      }

      // 4. Protocol Support
      if (protocol) {
        const legacyProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'];
        const isLegacy = legacyProtocols.includes(protocol);
        if (isLegacy) {
          findings.push({
            severity: 'high',
            category: 'tls',
            title: `Outdated Protocol Supported: ${protocol}`,
            description: 'The server supports legacy TLS protocols (TLSv1.0 or TLSv1.1) which contain known vulnerabilities.',
            recommendation: 'Disable TLS 1.0 and TLS 1.1 in your web server configurations. Require TLS 1.2 or TLS 1.3.'
          });
          score -= 15;
        }
      }

      // 5. Cipher Strength Check
      if (cipher && cipher.bits < 128) {
        findings.push({
          severity: 'medium',
          category: 'tls',
          title: `Weak Encryption Cipher Detected: ${cipher.name} (${cipher.bits} bits)`,
          description: 'The server supports weak ciphers with key lengths less than 128 bits.',
          recommendation: 'Disable weak ciphers and configure secure modern cipher suites (e.g. ECDHE-ECDSA-AES128-GCM-SHA256).'
        });
        score -= 10;
      }

      // 6. SANs Info
      if (cert.subjectaltname) {
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'Subject Alternative Names (SANs) detected',
          description: `Subject Alternative Names configured: ${cert.subjectaltname}`,
          recommendation: 'No action required.'
        });
      }

      // 7. Certificate Transparency (CT) Log Lookup via crt.sh
      try {
        const ctResults = await new Promise((resolve) => {
          const url = `https://crt.sh/?q=%25.${host}&output=json`;
          let isResolved = false;
          const safeResolve = (val) => { if (!isResolved) { isResolved = true; resolve(val); } };

          const req = https.get(url, { timeout: 6000 }, (res) => {
            if (res.statusCode !== 200) return safeResolve(null);
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
              body += chunk;
              if (body.length > 512000) { res.destroy(); safeResolve(body); }
            });
            res.on('end', () => safeResolve(body));
            res.on('error', () => safeResolve(null));
          });
          req.setTimeout(6000, () => { req.destroy(); safeResolve(null); });
          req.on('error', () => safeResolve(null));
        });

        if (ctResults) {
          try {
            const certs = JSON.parse(ctResults);
            const total = certs.length;

            const issuerCounts = {};
            for (const c of certs) {
              const issuer = c.issuer_name || 'Unknown';
              issuerCounts[issuer] = (issuerCounts[issuer] || 0) + 1;
            }
            const topIssuers = Object.entries(issuerCounts)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 3)
              .map(([name, count]) => `${name.match(/O=([^,]+)/)?.[1]?.trim() || name} (${count})`)
              .join(', ');

            const sorted = certs
              .filter(c => c.not_before)
              .sort((a, b) => new Date(b.not_before) - new Date(a.not_before));
            const newest = sorted[0];
            const newestDate = newest ? new Date(newest.not_before).toLocaleDateString() : 'unknown';

            findings.push({
              severity: 'info',
              category: 'tls',
              title: `Certificate Transparency: ${total} Certificate${total !== 1 ? 's' : ''} Found`,
              description: `crt.sh logs show ${total} certificate${total !== 1 ? 's' : ''} issued for this domain. Most recent issuance: ${newestDate}. Top issuers: ${topIssuers}.`,
              recommendation: 'Review the CT log for any unexpected certificate issuances. If you see certificates from CAs you did not authorize, investigate immediately and add a CAA record to restrict future issuance.'
            });

            if (total > 200) {
              findings.push({
                severity: 'info',
                category: 'tls',
                title: 'High Certificate Issuance Volume',
                description: `${total} certificates have been issued for this domain across CT logs. High volumes can indicate automated cert renewal, multi-environment deployments, or past ownership transfers.`,
                recommendation: 'Review CT logs at https://crt.sh/?q=' + host + ' to confirm all issuances are expected.'
              });
            }
          } catch {
            findings.push({
              severity: 'info',
              category: 'tls',
              title: 'High Certificate History Volume',
              description: `The certificate issuance log for ${host} is too large to parse automatically (>512KB).`,
              recommendation: `Manually audit historical issuances at https://crt.sh/?q=${host}`
            });
          }
        }
      } catch {
        findings.push({
          severity: 'info',
          category: 'tls',
          title: 'Certificate Transparency Lookup Unavailable',
          description: 'Could not reach crt.sh to perform CT log lookup. This check is non-critical.',
          recommendation: 'Manually review https://crt.sh for your domain if needed.'
        });
      }

    } catch (err) {
      findings.push({
        severity: 'high',
        category: 'tls',
        title: 'TLS scan error',
        description: `Failed to complete TLS verification: ${err.message}`,
        recommendation: 'Ensure HTTPS is configured and accessible on port 443.'
      });
      score = 0;
    }

    return {
      score: Math.max(0, score),
      findings,
      meta,
      summary
    };
  }
}

export default TlsScanner;