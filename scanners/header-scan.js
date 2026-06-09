import http from 'http';
import https from 'https';
import NormalizeHost from '../utils/normalizeHost.js';

class HeaderScanner {
  async scan(target) {
    const host = NormalizeHost.normalizeHost(target);
    if (!host) {
      return {
        score: 0,
        findings: [
          {
            severity: 'critical',
            title: 'Invalid Target',
            description: 'No valid host or domain name could be extracted from the target input.',
            recommendation: 'Provide a valid IP address or domain name.'
          }
        ]
      };
    }

    const findings = [];
    let score = 100;

    // Helper to fetch headers safely with redirect following and timeout guards
    const fetchHeaders = (url, redirectCount = 0) => {
      return new Promise((resolve) => {
        if (redirectCount > 3) {
          return resolve(null);
        }

        const client = url.startsWith('https') ? https : http;
        const options = {
          method: 'HEAD', // HEAD request is faster since we only care about headers
          timeout: 3000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; Three62SecurityScanner/1.0)'
          },
          rejectUnauthorized: false // Don't crash on invalid/expired certs
        };

        let req;
        let isResolved = false;

        const safeResolve = (val) => {
          if (!isResolved) {
            isResolved = true;
            if (req && !req.destroyed) req.destroy();
            resolve(val);
          }
        };

        try {
          req = client.request(url, options, (res) => {
            if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
              res.resume();
              let nextUrl = res.headers.location;
              if (!nextUrl.startsWith('http')) {
                try {
                  const parsed = new URL(url);
                  nextUrl = `${parsed.protocol}//${parsed.host}${nextUrl.startsWith('/') ? '' : '/'}${nextUrl}`;
                } catch {
                  return safeResolve(res.headers);
                }
              }
              fetchHeaders(nextUrl, redirectCount + 1).then(safeResolve);
            } else {
              res.resume();
              safeResolve(res.headers);
            }
          });

          req.on('error', (err) => {
            if (url.startsWith('https://') && redirectCount === 0) {
              const httpUrl = url.replace('https://', 'http://');
              fetchHeaders(httpUrl, redirectCount + 1).then(safeResolve);
            } else {
              safeResolve(null);
            }
          });

          req.on('timeout', () => safeResolve(null));
          req.end();
        } catch {
          safeResolve(null);
        }
      });
    };

    try {
      const headers = await fetchHeaders(`https://${host}`);

      if (!headers) {
        findings.push({
          severity: 'high',
          category: 'headers',
          title: 'Failed to Fetch HTTP Headers',
          description: `Could not establish a connection to ${host} to check security headers.`,
          recommendation: 'Verify the host is online and accepting connections on ports 80/443.'
        });
        return { score: 0, findings };
      }

      // 1. HTTP Strict-Transport-Security (HSTS)
      if (!headers['strict-transport-security']) {
        findings.push({
          severity: 'high',
          category: 'headers',
          title: 'Missing HTTP Strict-Transport-Security (HSTS)',
          description: 'The HSTS header is missing. This allows attackers to downgrade HTTPS connections to unencrypted HTTP.',
          recommendation: 'Add the Strict-Transport-Security header with a max-age directive.'
        });
        score -= 20;
      }

      // 2. Content-Security-Policy (CSP)
      if (!headers['content-security-policy']) {
        findings.push({
          severity: 'medium',
          category: 'headers',
          title: 'Missing Content-Security-Policy (CSP)',
          description: 'No Content-Security-Policy was detected. This increases vulnerability to Cross-Site Scripting (XSS) and data injection attacks.',
          recommendation: 'Define a robust CSP header to restrict loaded scripts, styles, and resources.'
        });
        score -= 15;
      }

      // 3. X-Frame-Options (Clickjacking defense)
      if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
        findings.push({
          severity: 'medium',
          category: 'headers',
          title: 'Missing Clickjacking Protection',
          description: 'Neither X-Frame-Options nor CSP frame-ancestors headers are present. The site can be embedded in an iframe on third-party sites.',
          recommendation: 'Configure X-Frame-Options to DENY or SAMEORIGIN.'
        });
        score -= 10;
      }

      // 4. X-Content-Type-Options
      if (headers['x-content-type-options']?.toLowerCase() !== 'nosniff') {
        findings.push({
          severity: 'low',
          category: 'headers',
          title: 'Missing X-Content-Type-Options nosniff Directive',
          description: 'The X-Content-Type-Options header is missing or improperly configured, allowing browsers to MIME-sniff response types.',
          recommendation: 'Set the X-Content-Type-Options header value explicitly to "nosniff".'
        });
        score -= 5;
      }

      // 5. Information Disclosure (Server Header Banner)
      if (headers['server'] || headers['x-powered-by']) {
        const platform = headers['x-powered-by'] || headers['server'];
        findings.push({
          severity: 'info',
          category: 'headers',
          title: 'Server Software Information Disclosure',
          description: `The server explicitly leaks software stack details via response headers: ${platform}`,
          recommendation: 'Remove or obfuscate the Server and X-Powered-By production response headers.'
        });
      }

    } catch (err) {
      findings.push({
        severity: 'high',
        category: 'headers',
        title: 'Header Evaluation Error',
        description: `An error occurred processing response headers: ${err.message}`,
        recommendation: 'Review scanner system log structures.'
      });
      score = 0;
    }

    return {
      score: Math.max(0, score),
      findings
    };
  }
}

export default HeaderScanner;