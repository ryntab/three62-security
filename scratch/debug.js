import PortScanner from '../scanners/port-scan.js';
import DnsScanner from '../scanners/dns-scan.js';
import TlsScanner from '../scanners/tls-scan.js';
import HeaderScanner from '../scanners/header-scan.js';
import ExposureScanner from '../scanners/exposure-scan.js';

const host = 'tendie.bot';

console.log('Starting PortScanner...');
try {
  const scanner = new PortScanner();
  const res = await scanner.scan(host);
  console.log('PortScanner done:', res);
} catch (e) {
  console.error('PortScanner failed:', e);
}

console.log('Starting DnsScanner...');
try {
  const scanner = new DnsScanner();
  const res = await scanner.scan(host);
  console.log('DnsScanner done:', res);
} catch (e) {
  console.error('DnsScanner failed:', e);
}

console.log('Starting TlsScanner...');
try {
  const scanner = new TlsScanner();
  const res = await scanner.scan(host);
  console.log('TlsScanner done:', res);
} catch (e) {
  console.error('TlsScanner failed:', e);
}

console.log('Starting HeaderScanner...');
try {
  const scanner = new HeaderScanner();
  const res = await scanner.scan(host);
  console.log('HeaderScanner done:', res);
} catch (e) {
  console.error('HeaderScanner failed:', e);
}

console.log('Starting ExposureScanner...');
try {
  const scanner = new ExposureScanner();
  const res = await scanner.scan(host);
  console.log('ExposureScanner done:', res);
} catch (e) {
  console.error('ExposureScanner failed:', e);
}

console.log('All debug scans completed.');
process.exit(0);
