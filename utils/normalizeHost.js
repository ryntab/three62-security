class NormalizeHost {
    normalizeHost(target) {
        if (!target) {
            return null;
        }

        // Remove protocol if present
        let host = target.replace(/^(https?:\/\/)?/, '');

        // Remove trailing slash if present
        host = host.replace(/\/$/, '');

        // Remove port if present
        host = host.replace(/:\d+$/, '');

        // Validate that we have a valid host
        if (!host || host.length === 0) {
            return null;
        }

        return host;
    }
}

export default new NormalizeHost();