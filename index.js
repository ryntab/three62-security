import Fastify from 'fastify';
import SecurityScanner from './scanners/index.js';
import dotenv from 'dotenv';
dotenv.config();

const app = Fastify({ logger: true });
const scanner = new SecurityScanner();

// ---------------------------------------------------------------------------
// Auth — validate Bearer token against SCANNER_TOKEN env var
// ---------------------------------------------------------------------------
const SCANNER_TOKEN = process.env.SCANNER_TOKEN;

if (!SCANNER_TOKEN) {
    console.error('[Server] FATAL: SCANNER_TOKEN environment variable is not set.');
    process.exit(1);
}

function validateBearer(request, reply) {
    const auth = request.headers['authorization'] ?? '';
    const [scheme, token] = auth.split(' ');

    if (scheme !== 'Bearer' || token !== SCANNER_TOKEN) {
        reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or missing Bearer token.' });
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Normalize URL → strip protocol, path, query string, port
// ---------------------------------------------------------------------------
function normalizeUrl(raw) {
    if (!raw) return null;

    let input = raw.trim();

    // Ensure there's a protocol so URL() can parse it
    if (!/^https?:\/\//i.test(input)) {
        input = `https://${input}`;
    }

    try {
        const parsed = new URL(input);
        // Return just the bare hostname (no port, no path, no trailing slash)
        return parsed.hostname || null;
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------------------
// POST /scan  { "url": "https://example.com/some/path" }
// GET  /scan?url=https://example.com/some/path
// ---------------------------------------------------------------------------
app.route({
    method: ['GET', 'POST'],
    url: '/scan',
    handler: async (request, reply) => {
        if (!validateBearer(request, reply)) return;

        const rawUrl =
            request.method === 'POST'
                ? request.body?.url
                : request.query?.url;

        const host = normalizeUrl(rawUrl);

        if (!host) {
            return reply.code(400).send({
                error: 'Bad Request',
                message: 'A valid "url" parameter is required.',
            });
        }

        try {
            const result = await scanner.scan(host);
            return reply.send(result);
        } catch (err) {
            request.log.error(err);
            return reply.code(500).send({
                error: 'Internal Server Error',
                message: err.message,
            });
        }
    },
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

try {
    await app.listen({ port: PORT, host: HOST });
    console.log(`[Server] Listening on http://${HOST}:${PORT}`);
} catch (err) {
    app.log.error(err);
    process.exit(1);
}