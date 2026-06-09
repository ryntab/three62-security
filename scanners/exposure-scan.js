import http from 'http';
import https from 'https';

// 1. DATA DICTIONARY: Centralized configuration for all endpoints
const EXPOSURE_TARGETS = [
  {
    path: '/robots.txt',
    category: 'seo',
    patterns: ['user-agent:', 'disallow:'],
    isExposedBad: false, // For SEO, we WANT it to be present
    severity: 'info',
    titlePresent: 'robots.txt Present',
    descPresent: 'A robots.txt file was found on the server.',
    recPresent: 'No action required.',
    titleMissing: 'Missing robots.txt',
    descMissing: 'No robots.txt file was found on the server. Search engines might index everything.',
    recMissing: 'Create a robots.txt file to guide search engine crawlers.',
    penalty: 0
  },
  {
    path: '/sitemap.xml',
    category: 'seo',
    patterns: ['<urlset', '<sitemapindex', 'sitemap'],
    isExposedBad: false,
    severity: 'info',
    titlePresent: 'sitemap.xml Present',
    descPresent: 'A sitemap.xml file was found on the server.',
    recPresent: 'No action required.',
    titleMissing: 'Missing sitemap.xml',
    descMissing: 'No sitemap.xml file was found. Search engines might have difficulty finding all pages.',
    recMissing: 'Generate a sitemap.xml file and place it at the root of your site.',
    penalty: 0
  },
  {
    path: '/llms.txt',
    category: 'seo',
    patterns: ['LLMS'],
    isExposedBad: false,
    severity: 'info',
    titlePresent: 'LLMS Text File Present',
    descPresent: 'A LLMS text file was found on the server.',
    recPresent: 'No action required.',
    titleMissing: 'LLMS Text File Not Found',
    descMissing: 'A LLMS text file was not found on the server.',
    recMissing: 'No action required.',
    penalty: 0
  },
  {
    path: '/wp-login.php',
    category: 'exposure',
    patterns: ['wp-login', 'user_login', 'wp-submit', 'wordpress'],
    isExposedBad: true, // For security endpoints, exposure is bad
    severity: 'low',
    titlePresent: 'WordPress Login Page Exposed',
    descPresent: 'A WordPress login page (wp-login.php) was found. Exposed login pages are targets for brute-force attacks.',
    recPresent: 'Restrict access to wp-login.php by IP, rename the login path, or implement strong MFA/rate limiting.',
    penalty: 5
  },
  {
    path: '/xmlrpc.php',
    category: 'exposure',
    patterns: ['xmlrpc', 'XML-RPC server accepts POST requests only'],
    isExposedBad: true,
    severity: 'low',
    titlePresent: 'WordPress XML-RPC Exposed',
    descPresent: 'The xmlrpc.php endpoint appears to be active. This interface can be exploited for brute-force or DDoS reflection attacks.',
    recPresent: 'Disable xmlrpc.php in your web server configuration or via a security plugin if it is not required.',
    penalty: 5
  },
  {
    path: '/readme.html',
    category: 'exposure',
    patterns: ['wordpress', 'semantic versioning', 'readme'],
    isExposedBad: true,
    severity: 'info',
    titlePresent: 'WordPress Readme File Exposed',
    descPresent: 'The readme.html file is accessible. This file discloses installation details and potentially the WordPress version.',
    recPresent: 'Remove the readme.html file from the root directory.',
    penalty: 0
  },
  {
    path: '/server-status',
    category: 'exposure',
    patterns: ['Apache Server Status', 'Server Version', 'Server uptime', 'Total accesses'],
    isExposedBad: true,
    severity: 'medium',
    titlePresent: 'Apache Server Status Exposed',
    descPresent: 'The server-status endpoint is publicly accessible. This leaks active client requests, IP addresses, and resource usage details.',
    recPresent: 'Restrict access to the /server-status directive in your Apache configuration to local loopback/trusted IPs only.',
    penalty: 10
  },
  {
    path: '/phpinfo.php',
    category: 'exposure',
    patterns: ['phpinfo()', 'php version', 'system info', 'registered streams', 'allow_url_fopen'],
    isExposedBad: true,
    severity: 'high',
    titlePresent: 'PHP Info Page Exposed',
    descPresent: 'A phpinfo() output page is publicly accessible. This leaks detailed server environment variables, loaded modules, and config parameters.',
    recPresent: 'Remove the phpinfo.php file from the web root directory immediately.',
    penalty: 15
  },
  {
    path: '/.env',
    category: 'exposure',
    patterns: ['DB_HOST', 'APP_ENV', 'AWS_ACCESS_KEY', 'SECRET_KEY', 'PORT=', 'DB_DATABASE', 'JWT_SECRET'],
    isExposedBad: true,
    severity: 'critical',
    titlePresent: 'Environment Secrets File Exposed',
    descPresent: 'A .env environment configuration file was found. This contains highly sensitive credentials, database keys, and API secrets.',
    recPresent: 'Secure your web server configuration to deny access to hidden files/dotfiles, or move the .env file outside the public web root.',
    penalty: 25
  }
];

class ExposureScanner {
  async scan(host) {
    const findings = [];
    const seoFindings = [];
    let score = 100;

    // Helper to request a URL path and verify status code/content patterns
    const probePath = (url, redirectCount = 0) => {
      return new Promise((resolve) => {
        if (redirectCount > 3) {
          return resolve({ status: 0, data: '' });
        }

        const client = url.startsWith('https') ? https : http;
        const options = {
          method: 'GET',
          timeout: 3000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; Three62SecurityScanner/1.0)'
          },
          rejectUnauthorized: false
        };

        let req;
        let isResolved = false;

        const safeResolve = (value) => {
          if (!isResolved) {
            isResolved = true;
            if (req && !req.destroyed) {
              req.destroy();
            }
            resolve(value);
          }
        };

        try {
          req = client.get(url, options, (res) => {
            if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
              res.resume();
              let nextUrl = res.headers.location;
              if (!nextUrl.startsWith('http')) {
                try {
                  const parsed = new URL(url);
                  nextUrl = `${parsed.protocol}//${parsed.host}${nextUrl.startsWith('/') ? '' : '/'}${nextUrl}`;
                } catch {
                  return safeResolve({ status: res.statusCode, data: '' });
                }
              }
              probePath(nextUrl, redirectCount + 1).then(safeResolve);
            } else {
              let data = '';
              res.setEncoding('utf8');

              res.on('data', (chunk) => {
                data += chunk;
                if (data.length > 2048) {
                  res.destroy();
                  safeResolve({ status: res.statusCode, data });
                }
              });

              res.on('end', () => safeResolve({ status: res.statusCode, data }));
              res.on('error', () => safeResolve({ status: res.statusCode || 0, data: '' }));
            }
          });

          req.on('error', (err) => {
            if (url.startsWith('https://') && redirectCount === 0) {
              const httpUrl = url.replace('https://', 'http://');
              probePath(httpUrl, redirectCount + 1).then(safeResolve);
            } else {
              safeResolve({ status: 0, data: '' });
            }
          });

          req.on('timeout', () => safeResolve({ status: 0, data: '' }));
          req.end();

        } catch {
          safeResolve({ status: 0, data: '' });
        }
      });
    };

    // Helper to evaluate if a probe is a true positive
    const checkExposure = async (path, expectedPatterns) => {
      const res = await probePath(`https://${host}${path}`);
      if (res.status === 200) {
        if (expectedPatterns && expectedPatterns.length > 0) {
          return expectedPatterns.some(pattern => res.data.toLowerCase().includes(pattern.toLowerCase()));
        }
        return true;
      }
      if (path === '/xmlrpc.php') {
        return (
          res.status === 405 &&
          res.data.toLowerCase().includes('xml-rpc')
        );
      }
      return false;
    };

    // 2. DYNAMIC EVALUATION ENGINE: Loops through the dictionary cleanly
    try {
      // Check how the host handles a completely fake asset path first
      const wildcardCheck = await probePath(`https://${host}/vulnerability-false-positive-canary-test-xyz`);
      const isWildcardServer = wildcardCheck.status === 200;

      for (const target of EXPOSURE_TARGETS) {
        let isExposed = await checkExposure(target.path, target.patterns);

        // If it's a wildcard server and it's a security target, apply an extra strict match layer
        if (isExposed && isWildcardServer && target.isExposedBad) {
          // Re-probe path to verify it contains multiple high-entropy keywords, 
          // ensuring it's the raw configuration stream and not a decorative catch-all page
          const rawCheck = await probePath(`https://${host}${target.path}`);
          if (target.path === '/.env') {
            // Require at least TWO structural keys to flag a true .env compromise
            const matchCount = target.patterns.filter(p => rawCheck.data.includes(p)).length;
            if (matchCount < 2) isExposed = false;
          }
        }

        const outputQueue = target.category === 'seo' ? seoFindings : findings;

        if (isExposed) {
          // It's exposed! If it's a security risk (isExposedBad), deduct points.
          if (target.isExposedBad) {
            score -= target.penalty;
          }

          outputQueue.push({
            severity: target.severity,
            category: target.category,
            title: target.titlePresent,
            description: target.descPresent,
            recommendation: target.recPresent
          });
        } else {
          // It's not exposed! (Great for security files, but means missing files for SEO)
          // Only log a finding if the absence of the file is noteworthy (like a missing robots.txt)
          if (!target.isExposedBad) {
            outputQueue.push({
              severity: target.severity,
              category: target.category,
              title: target.titleMissing,
              description: target.descMissing,
              recommendation: target.recMissing
            });
          }
        }
      }
    } catch (err) {
      findings.push({
        severity: 'info',
        category: 'exposure',
        title: 'Exposure scan error',
        description: `Failed to complete path exposure probe: ${err.message}`,
        recommendation: 'Ensure the server is online and accepting HTTP requests.'
      });
    }

    return {
      score: Math.max(0, score),
      findings,
      seoFindings
    };
  }
}

export default ExposureScanner;