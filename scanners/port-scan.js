import net from 'net';
import portMap from './lib/port-map.json' with { type: 'json' };

class PortScanner {
  async scan(host) {
    const findings = [];
    let score = 100;

    // Standardized structural objects matching the TLS layer
    let meta = {
      scannedPortsCount: 0,
      openPorts: []
    };

    let summary = {
      has_exposed_ports: false,
      open_ports_count: 0
    };

    // Helper to probe a single port
    const probePort = (hostname, port, timeout = 1000) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();

        socket.setTimeout(timeout);

        socket.connect(port, hostname, () => {
          socket.destroy();
          resolve(true); // Open
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve(false); // Closed / Filtered
        });

        socket.on('error', () => {
          socket.destroy();
          resolve(false); // Closed
        });
      });
    };

    try {
      const portsToScan = Object.keys(portMap).filter(p => p !== '80' && p !== '443');
      meta.scannedPortsCount = portsToScan.length;

      // Concurrency control: Process ports in parallel chunks to prevent EMFILE socket depletion
      const CONCURRENCY_LIMIT = 10;
      for (let i = 0; i < portsToScan.length; i += CONCURRENCY_LIMIT) {
        const chunk = portsToScan.slice(i, i + CONCURRENCY_LIMIT);

        await Promise.all(chunk.map(async (portStr) => {
          const port = parseInt(portStr, 10);
          const isOpen = await probePort(host, port);

          if (isOpen) {
            const info = portMap[portStr] || {};
            const serviceName = info.service || 'Unknown Service';

            // Track internally for metadata payloads
            meta.openPorts.push({
              port,
              service: serviceName,
              severity: info.severity || 'low'
            });

            const defaultRec = `Close port ${port} at the firewall level if access is not required by external users, or restrict access to specific trusted IPs.`;

            findings.push({
              severity: info.severity || 'low',
              category: 'ports',
              title: `Open Port: ${port} (${serviceName})`,
              description: `${info.description || 'Service'} is publicly accessible on port ${port}.`,
              recommendation: info.recommendation || defaultRec,
              ...(info.tags && { tags: info.tags })
            });
          }
        }));
      }

      // Sort open ports array numerically for cleaner UI presentations
      meta.openPorts.sort((a, b) => a.port - b.port);

      // Populate easy-access quick summary fields
      summary.open_ports_count = meta.openPorts.length;
      summary.has_exposed_ports = meta.openPorts.length > 0;

      // Calculate score deduction based on aggregated findings
      for (const finding of findings) {
        if (finding.severity === 'critical') score -= 25;
        else if (finding.severity === 'high') score -= 15;
        else if (finding.severity === 'medium') score -= 10;
        else if (finding.severity === 'low') score -= 5;
      }

    } catch (err) {
      findings.push({
        severity: 'high',
        category: 'ports',
        title: 'Port scan error',
        description: `Failed to complete port scanning: ${err.message}`,
        recommendation: 'Check network connectivity and ensure the target host is reachable.'
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

export default PortScanner;