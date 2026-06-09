import PortScanner from './port-scan.js';
import DnsScanner from './dns-scan.js';
import TlsScanner from './tls-scan.js';
import HeaderScanner from './header-scan.js';
import ExposureScanner from './exposure-scan.js';
import BlacklistScanner from './blacklist-scan.js';
import MtaStsScanner from './mta-sts-scan.js';
import NetworkScanner from './network-scan.js';

class SecurityScanner {
  constructor() {
    this.scanners = {
      network: new NetworkScanner(),
      dns: new DnsScanner(),
      tls: new TlsScanner(),
      headers: new HeaderScanner(),
      ports: new PortScanner(),
      blacklist: new BlacklistScanner(),
      mtaSts: new MtaStsScanner(),
      exposure: new ExposureScanner(),
    };
  }

  // --------------------------------------------------------------------------
  // Normalize host — strips protocol, path, port
  // --------------------------------------------------------------------------
  normalizeHost(target) {
    if (!target) return '';
    let host = target.trim();
    if (host.includes('://')) host = host.split('://')[1];
    host = host.split('/')[0];
    host = host.split(':')[0];
    return host;
  }

  // --------------------------------------------------------------------------
  // Domain Health — aggregated pass/fail verdict across all security pillars
  // --------------------------------------------------------------------------
  computeDomainHealth(allFindings) {
    const pillars = {
      dns: { label: 'DNS Configuration', pass: true, issues: [] },
      email: { label: 'Email Authentication (SPF/DKIM/DMARC)', pass: true, issues: [] },
      tls: { label: 'TLS / HTTPS', pass: true, issues: [] },
      headers: { label: 'Security Headers', pass: true, issues: [] },
      blacklist: { label: 'Blacklist Status', pass: true, issues: [] },
      mtaSts: { label: 'MTA-STS / Email in Transit', pass: true, issues: [] },
    };

    for (const finding of allFindings) {
      const sev = finding.severity?.toLowerCase();
      const cat = finding.category?.toLowerCase();
      const isProblematic = sev === 'critical' || sev === 'high' || sev === 'medium';
      if (!isProblematic) continue;

      if (cat === 'dns') {
        pillars.dns.pass = false;
        pillars.dns.issues.push(finding.title);
      }
      // Route email-specific findings checking explicitly by category or signature tags
      if (cat === 'email' || (cat === 'dns' && (
        finding.title.includes('SPF') ||
        finding.title.includes('DMARC') ||
        finding.title.includes('DKIM') ||
        finding.title.includes('MX')
      ))) {
        pillars.email.pass = false;
        pillars.email.issues.push(finding.title);
      }
      if (cat === 'tls') {
        pillars.tls.pass = false;
        pillars.tls.issues.push(finding.title);
      }
      if (cat === 'headers') {
        pillars.headers.pass = false;
        pillars.headers.issues.push(finding.title);
      }
      if (cat === 'blacklist') {
        pillars.blacklist.pass = false;
        pillars.blacklist.issues.push(finding.title);
      }
      if (cat === 'mta-sts') {
        pillars.mtaSts.pass = false;
        pillars.mtaSts.issues.push(finding.title);
      }
    }

    const passingCount = Object.values(pillars).filter(p => p.pass).length;
    const totalPillars = Object.keys(pillars).length;
    const overallPass = passingCount === totalPillars;

    return {
      overall: overallPass ? 'pass' : passingCount >= totalPillars * 0.75 ? 'warning' : 'fail',
      pillars
    };
  }

  // --------------------------------------------------------------------------
  // Email Deliverability — pass/warning/fail verdict for mail sending
  // --------------------------------------------------------------------------
  computeEmailDeliverability(allFindings) {
    const checks = {
      hasMx: { label: 'MX Records', pass: true },
      spf: { label: 'SPF Record', pass: true },
      dkim: { label: 'DKIM Signing', pass: true },
      dmarc: { label: 'DMARC Policy', pass: true },
      dmarcEnforced: { label: 'DMARC Enforcement', pass: true },
      ptr: { label: 'Reverse DNS (PTR)', pass: true },
      blacklist: { label: 'Blacklist Clean', pass: true },
      mtaSts: { label: 'MTA-STS Enforce', pass: true },
      tlsRpt: { label: 'TLS-RPT', pass: true },
    };

    // Track if we specifically hit certain records to manage defaults gracefully
    let housesActiveBlacklistVulnerability = false;

    for (const finding of allFindings) {
      const title = finding.title || '';
      const cat = finding.category || '';
      const sev = finding.severity || '';
      const isIssue = ['medium', 'high', 'critical'].includes(sev);

      // MX
      if (title.includes('No MX Records') || (cat === 'dns' && title.includes('MX') && isIssue)) {
        checks.hasMx.pass = false;
      }

      // SPF
      if (title.includes('Missing SPF') || title.includes('Weak SPF') || (cat === 'dns' && title.includes('SPF') && isIssue)) {
        checks.spf.pass = false;
      }

      // DKIM
      if (title.includes('No DKIM') || (cat === 'dns' && title.includes('DKIM') && isIssue)) {
        checks.dkim.pass = false;
      }

      // DMARC
      if (title.includes('Missing DMARC') || (cat === 'dns' && title.includes('DMARC') && isIssue)) {
        checks.dmarc.pass = false;
      }
      if (title.includes('DMARC Policy: none')) {
        checks.dmarcEnforced.pass = false;
      }

      // PTR / Reverse DNS
      if (title.includes('Reverse DNS') && (title.includes('No Reverse') || title.includes('Mismatch') || isIssue)) {
        checks.ptr.pass = false;
      }

      // Blacklist Status Parsing (Safe conditional mapping targeting structural issue tags)
      if (cat === 'blacklist' && isIssue) {
        housesActiveBlacklistVulnerability = true;
      }

      // MTA-STS
      if (cat === 'mta-sts' && (title.includes('Not Configured') || title.includes('testing') || title.includes('none') || isIssue)) {
        if (!title.includes('enforce ✓')) {
          checks.mtaSts.pass = false;
        }
      }

      // TLS-RPT
      if (title.includes('TLS-RPT Not Configured') || (cat === 'mta-sts' && title.includes('TLS-RPT') && isIssue)) {
        checks.tlsRpt.pass = false;
      }
    }

    // Force explicit structural evaluation onto the blacklist status block
    checks.blacklist.pass = !housesActiveBlacklistVulnerability;

    // Scoring: weighted pass counts
    const critical = [checks.hasMx, checks.spf, checks.dkim, checks.dmarc, checks.blacklist];
    const recommended = [checks.dmarcEnforced, checks.ptr, checks.mtaSts, checks.tlsRpt];

    const criticalFails = critical.filter(c => c.pass === false).length;
    const recommendedFails = recommended.filter(c => c.pass === false).length;

    let verdict = 'pass';
    if (criticalFails > 0) {
      verdict = 'fail';
    } else if (recommendedFails > 0) {
      verdict = 'warning';
    }

    return { verdict, checks };
  }

  // --------------------------------------------------------------------------
  // Main scan orchestrator
  // --------------------------------------------------------------------------
  async scan(target) {
    const host = this.normalizeHost(target);
    if (!host) {
      return {
        score: 0,
        findings: [{
          severity: 'critical',
          title: 'Invalid Target',
          description: 'No valid host or domain name could be extracted from the target input.',
          recommendation: 'Provide a valid IP address or domain name.'
        }]
      };
    }

    console.log(`[Engine] Starting scan for: ${host}`);

    const scanKeys = Object.keys(this.scanners);
    const scanPromises = scanKeys.map(key => this.scanners[key].scan(host));
    const results = await Promise.allSettled(scanPromises);

    const report = {
      host,
      timestamp: new Date().toISOString(),
      score: 100,
      scans: {}
    };

    const allFindings = [];
    const seoFindings = [];

    results.forEach((res, index) => {
      const key = scanKeys[index];

      if (res.status === 'fulfilled') {
        console.log(`[Engine] ✓ [${key}] completed`);
        report.scans[key] = {
          failed: false,
          score: res.value.score,
          findings: res.value.findings
        };

        if (res.value.seoFindings) {
          report.scans[key].seoFindings = res.value.seoFindings;
          seoFindings.push(...res.value.seoFindings);
        }

        if (Array.isArray(res.value.findings)) {
          allFindings.push(...res.value.findings);
        }
      } else {
        console.error(`❌ [Engine] [${key}] FAILED:`, res.reason);
        report.scans[key] = {
          failed: true,
          score: 0,
          error: {
            message: res.reason?.message || String(res.reason),
            stack: res.reason?.stack || null
          },
          findings: [{
            severity: 'high',
            category: key,
            title: `Scanner Error: ${key}`,
            description: `The ${key} scanner failed to execute: ${res.reason?.message || res.reason}`,
            recommendation: 'Inspect scanner logs for syntax or runtime errors.'
          }]
        };
        allFindings.push(...report.scans[key].findings);
      }
    });

    // --------------------------------------------------------------------------
    // Advanced Deductive Risk Scoring Model (Replaces Brittle Flat Averaging)
    // --------------------------------------------------------------------------
    let totalDeductions = 0;
    allFindings.forEach(f => {
      const sev = f.severity?.toLowerCase();
      // Skip processing pure info logs or structural passes
      if (sev === 'info' || sev === 'low') return;

      if (sev === 'critical') totalDeductions += 25;
      if (sev === 'high') totalDeductions += 15;
      if (sev === 'medium') totalDeductions += 10;
    });

    // Sub-scanner baseline weight contributor fallback logic
    const scanScores = Object.values(report.scans).map(s => s.score);
    const averageScannerScore = scanScores.length > 0
      ? scanScores.reduce((sum, val) => sum + val, 0) / scanScores.length
      : 100;

    // Merge systemic vulnerability deductions with individual module outputs
    const calculatedScore = Math.min(averageScannerScore, 100 - totalDeductions);
    report.score = Math.max(0, Math.round(calculatedScore));

    report.findings = allFindings;
    report.seoFindings = seoFindings;

    // Severity summary
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    allFindings.forEach(f => {
      const sev = f.severity?.toLowerCase();
      if (Object.hasOwn(summary, sev)) summary[sev]++;
    });
    report.summary = summary;

    // Domain Health aggregate
    report.domainHealth = this.computeDomainHealth(allFindings);

    // Email Deliverability aggregate
    report.emailDeliverability = this.computeEmailDeliverability(allFindings);

    console.log(`[Engine] Scan complete — Score: ${report.score} | Health: ${report.domainHealth.overall} | Email: ${report.emailDeliverability.verdict}`);
    console.log(`[Engine] Findings: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info`);

    return report;
  }
}

export default SecurityScanner;