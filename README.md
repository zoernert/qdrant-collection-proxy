# Qdrant Collection Proxy

Read-only JWT-protected proxy that exposes a single Qdrant collection over a minimal subset of the REST API suitable for RAG usage.

## Quick start

1. Copy and adjust `.env`:

   - `QDRANT_URL` points to your internal Qdrant
   - `QDRANT_API_KEY` if your Qdrant requires it
   - `QDRANT_COLLECTION_NAME` the collection to expose
   - `JWT_SECRET` a strong secret for signing access tokens
   - optional: `PORT`, `HOST`, `JWT_ISSUER`, `QDRANT_INSECURE_TLS=true` for self-signed certs
   - optional: `PROXY_IP_WHITELIST` (comma-separated IP/CIDR) to bypass JWT for trusted sources
   - optional: `TRUST_PROXY=true` if running behind a reverse proxy (uses X-Forwarded-For)

2. Install and run:

   npm install
   npm run start

3. Issue a client token (default 1h):

   npm run token -- alice 1h

4. Call the proxy with the token:

   curl -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     http://localhost:8787/collections/<name>/points/search \
     -d '{"vector": [0.1,0.2], "limit": 5}'

Note: `<name>` must equal the configured `QDRANT_COLLECTION_NAME`.

## Docker

Build and run:

   docker build -t qdrant-collection-proxy .
   docker run --rm -p 8787:8787 --env-file .env qdrant-collection-proxy

## OpenAPI

The file `openapi.json` describes the supported proxy endpoints for easy import into API tools.

## Endpoints exposed (read-only)

- POST `/collections/:name/points/search`
- POST `/collections/:name/points/query`
- POST `/collections/:name/points/recommend`
- POST `/collections/:name/points/scroll`
- POST `/collections/:name/points` (retrieve by ids)
- POST `/collections/:name/points/count`
- GET  `/collections/:name` (collection info)

All other endpoints are blocked with 403.

## Token claims

Tokens include claims:

- `sub`: subject (client id)
- `scope`: always `read`
- `col`: bound collection (informational)

Validation uses `issuer` and `secret`. Rotation can be handled by changing `JWT_SECRET`.

## Security notes

- Only read endpoints are proxied. Writes/deletes/updates are blocked.
- The collection name in path must match the configured one; otherwise 403.
- If your upstream Qdrant uses self-signed TLS, set `QDRANT_INSECURE_TLS=true`.
 - IP Whitelist: Set `PROXY_IP_WHITELIST` like `127.0.0.1/32,::1/128,10.0.0.0/8`. Requests from these IPs skip JWT validation. If behind a proxy, enable `TRUST_PROXY=true` and ensure correct X-Forwarded-For handling.
 - RapidAPI bypass: If the header `X-RapidAPI-User` is present, the request is auto-whitelisted (JWT not required). The user context is set to `rapidapi:<value>`.
