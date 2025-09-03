import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import https from 'https';
import ipaddr from 'ipaddr.js';

// Config
const {
  PORT = 8787,
  HOST = '0.0.0.0',
  JWT_SECRET,
  JWT_ISSUER = 'qdrant-collection-proxy',
  QDRANT_URL,
  QDRANT_API_KEY,
  QDRANT_COLLECTION_NAME,
  QDRANT_INSECURE_TLS,
  TRUST_PROXY = 'false',
  PROXY_IP_WHITELIST,
} = process.env;

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment');
  process.exit(1);
}
if (!QDRANT_URL || !QDRANT_COLLECTION_NAME) {
  console.error('Missing QDRANT_URL or QDRANT_COLLECTION_NAME in environment');
  process.exit(1);
}

// Axios client for Qdrant
const httpsAgent = process.env.QDRANT_INSECURE_TLS === 'true'
  ? new https.Agent({ rejectUnauthorized: false })
  : undefined;

const http = axios.create({
  baseURL: QDRANT_URL,
  headers: {
    ...(QDRANT_API_KEY ? { 'api-key': QDRANT_API_KEY } : {}),
    'Content-Type': 'application/json',
  },
  // Allow self-signed if requested
  httpsAgent,
  validateStatus: () => true,
});

// Express app
const app = express();
app.disable('x-powered-by');
if (TRUST_PROXY === 'true') app.set('trust proxy', true);
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(morgan('combined'));

// Normalize client-provided api-key header to Authorization if present
app.use((req, _res, next) => {
  if (!req.headers.authorization && req.headers['api-key']) {
    req.headers.authorization = `Bearer ${req.headers['api-key']}`;
  }
  next();
});

// Parse whitelist from env (comma-separated CIDR or IP)
const whitelistCidrs = (PROXY_IP_WHITELIST || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((cidr) => {
    try {
      if (cidr.includes('/')) {
        return ipaddr.parseCIDR(cidr); // returns [addr, prefix]
      } else {
        const addr = ipaddr.parse(cidr);
        const prefix = addr.kind() === 'ipv4' ? 32 : 128;
        return [addr, prefix];
      }
    } catch {
      return null;
    }
  })
  .filter(Boolean);

function isWhitelistedIp(remote) {
  if (!whitelistCidrs.length) return false;
  try {
    const addr = ipaddr.parse(remote);
    // Normalize IPv4-mapped IPv6
    const normalized = addr.kind() === 'ipv6' && addr.isIPv4MappedAddress() ? addr.toIPv4Address() : addr;
  return whitelistCidrs.some((rule) => normalized.match(rule));
  } catch {
    return false;
  }
}

function getClientIp(req) {
  try {
    if (TRUST_PROXY === 'true') {
      const xff = (req.headers['x-forwarded-for'] || '').toString();
      if (xff) {
        const first = xff.split(',')[0].trim();
        if (first) return first.replace('::ffff:', '');
      }
    }
    const ip = (req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || '').toString();
    return ip.replace('::ffff:', '');
  } catch {
    return '';
  }
}

// JWT auth middleware
function authMiddleware(req, res, next) {
  try {
    const clientIp = getClientIp(req);
    if (isWhitelistedIp(clientIp)) {
      req.user = { sub: 'whitelist', scope: 'read', ip: clientIp };
      return next();
    }
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing Bearer token' });
    const payload = jwt.verify(token, JWT_SECRET, { issuer: JWT_ISSUER });
    // Optional: restrict to collection via claim; for now we enforce single collection globally
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Utility: enforce only the configured collection name in request bodies/params
function ensureCollection(reqCollection) {
  if (reqCollection && reqCollection !== QDRANT_COLLECTION_NAME) {
    const e = new Error(`Access limited to collection ${QDRANT_COLLECTION_NAME}`);
    e.status = 403;
    throw e;
  }
}

// Error wrapper
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  const status = e.status || 500;
  res.status(status).json({ error: e.message || 'Internal error' });
});

// Health
app.get('/health', (req, res) => {
  const debug = process.env.PROXY_DEBUG_WHITELIST === 'true';
  const base = { ok: true, collection: QDRANT_COLLECTION_NAME };
  if (debug) {
    const ip = getClientIp(req);
    return res.json({ ...base, clientIp: ip, whitelisted: isWhitelistedIp(ip) });
  }
  res.json(base);
});

// Debug endpoints (dev only)
if (process.env.PROXY_DEBUG_WHITELIST === 'true') {
  app.get('/_debug/ip', (req, res) => {
    res.json({
      ip: getClientIp(req),
      reqIp: req.ip,
      ips: req.ips,
      remoteAddress: req.socket?.remoteAddress || req.connection?.remoteAddress,
      xff: req.headers['x-forwarded-for'] || null,
      whitelist: (PROXY_IP_WHITELIST || '').split(',').map((s) => s.trim()).filter(Boolean),
    });
  });
  app.get('/_debug/check', (req, res) => {
    const ip = (req.query.ip || '').toString();
    if (!ip) return res.status(400).json({ error: 'ip query param required' });
    return res.json({ ip, whitelisted: isWhitelistedIp(ip) });
  });
}

// Auth-protected routes
app.use(authMiddleware);

// Robust masked collections list (handles both GET and HEAD)
app.use((req, res, next) => {
  if ((req.method === 'GET' || req.method === 'HEAD') && (req.path === '/collections' || req.path === '/collections/')) {
    if (req.method === 'HEAD') return res.status(200).end();
    return res.json({ status: 'ok', result: { collections: [{ name: QDRANT_COLLECTION_NAME }] } });
  }
  return next();
});

// Masked collections list: expose only the configured collection
app.get('/collections', (_req, res) => {
  res.json({ status: 'ok', result: { collections: [{ name: QDRANT_COLLECTION_NAME }] } });
});

// Strict guard: deny non-GET or other verbs on /collections
app.all('/collections', (req, res) => {
  if (req.method.toUpperCase() === 'GET') return res.status(405).json({ error: 'Method Not Allowed' });
  return res.status(403).json({ error: 'Endpoint not available via proxy' });
});

// Exposed, read-only subset of Qdrant endpoints for a single collection
// 1) Vectors search: POST /collections/:name/points/search
app.post('/collections/:name/points/search', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  // Enforce collection in path only; forward as-is
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/search`, body);
  res.status(response.status).json(response.data);
}));

// 1b) Batch search
app.post('/collections/:name/points/search/batch', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/search/batch`, body);
  res.status(response.status).json(response.data);
}));

// 1c) Grouped search (if supported by upstream)
app.post('/collections/:name/points/search/groups', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/search/groups`, body);
  res.status(response.status).json(response.data);
}));

// 2) Query DSL: POST /collections/:name/points/query
app.post('/collections/:name/points/query', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/query`, body);
  res.status(response.status).json(response.data);
}));

// 2b) Query batch (if supported)
app.post('/collections/:name/points/query/batch', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/query/batch`, body);
  res.status(response.status).json(response.data);
}));

// 3) Recommend: POST /collections/:name/points/recommend
app.post('/collections/:name/points/recommend', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/recommend`, body);
  res.status(response.status).json(response.data);
}));

// 3b) Recommend batch
app.post('/collections/:name/points/recommend/batch', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/recommend/batch`, body);
  res.status(response.status).json(response.data);
}));

// 4) Scroll (read/list points): POST /collections/:name/points/scroll
app.post('/collections/:name/points/scroll', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/scroll`, body);
  res.status(response.status).json(response.data);
}));

// 5) Retrieve points by ids: POST /collections/:name/points/retrieve
app.post('/collections/:name/points/retrieve', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/retrieve`, body);
  res.status(response.status).json(response.data);
}));

// 5b) Compatibility handler for clients calling POST /collections/:name/points with retrieve body
app.post('/collections/:name/points', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  // Allow only retrieve-like payloads: must have ids array, and must NOT contain write-like fields
  const hasIds = Array.isArray(body.ids);
  const forbiddenKeys = ['points', 'points_batch', 'payload', 'vectors', 'upsert', 'delete', 'set_payload'];
  const containsForbidden = Object.keys(body || {}).some((k) => forbiddenKeys.includes(k));
  if (!hasIds || containsForbidden) {
    const e = new Error('Endpoint not available via proxy');
    e.status = 403;
    throw e;
  }
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/retrieve`, body);
  res.status(response.status).json(response.data);
}));

// 6) Collection info: GET /collections/:name
app.get('/collections/:name', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const response = await http.get(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}`);
  res.status(response.status).json(response.data);
}));

// 6a) Payload schema: GET /collections/:name/payload_schema
app.get('/collections/:name/payload_schema', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const response = await http.get(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/payload_schema`);
  res.status(response.status).json(response.data);
}));

// 6b) Collection exists: HEAD /collections/:name
app.head('/collections/:name', (req, res) => {
  try {
    ensureCollection(req.params.name);
    return res.status(200).end();
  } catch (_e) {
    return res.status(404).end();
  }
});

// Block non-GET on collection root
app.all('/collections/:name', (req, res, next) => {
  if (req.method.toUpperCase() === 'GET') return next();
  return res.status(403).json({ error: 'Endpoint not available via proxy' });
});

// 7) Retrieve point by id: GET /collections/:name/points/:id
app.get('/collections/:name/points/:id', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const { id } = req.params;
  const response = await http.get(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/${encodeURIComponent(id)}`);
  res.status(response.status).json(response.data);
}));

// 8) Count points: POST /collections/:name/points/count
app.post('/collections/:name/points/count', wrap(async (req, res) => {
  ensureCollection(req.params.name);
  const body = req.body || {};
  const response = await http.post(`/collections/${encodeURIComponent(QDRANT_COLLECTION_NAME)}/points/count`, body);
  res.status(response.status).json(response.data);
}));

// Block any other methods/endpoints to ensure read-only exposure
app.all('/collections/:name/*', (req, res) => {
  return res.status(403).json({ error: 'Endpoint not available via proxy' });
});

// Start server
app.listen(Number(PORT), HOST, () => {
  console.log(`Qdrant Collection Proxy listening on http://${HOST}:${PORT} for collection ${QDRANT_COLLECTION_NAME}`);
});
