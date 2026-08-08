# lnSwitchboard <img align="right" width="120" src="https://raw.githubusercontent.com/RyleaStark/lnSwitchboard/06b3a888fe95d4f07653651edba6c99d0bda0b3d/frontend/static/icon.svg" alt="lnSwitchboard logo" />

**Turns any Lightning node into a sovereign Lightning Address switchboard that speaks LNURL, watches your liquidity, and lets you manage identities without touching the command line.**

Published on the [Umbrel App Store](https://umbrel.com/), shipped on [Docker Hub](https://hub.docker.com/r/ryleastark/lnswitchboard) and as a public [GHCR package](https://github.com/RyleaStark/lnSwitchboard/pkgs/container/lnswitchboard).

---

## What is lnSwitchboard? (ELI5)

Think of your Lightning node as a call center. Every time someone zaps `yourname@yourdomain`, a little switchboard operator (lnSwitchboard) picks up, checks who’s calling, makes sure the line isn’t being spammed, and then patches the call through with a freshly minted invoice. The operator keeps notes about every call, so you can later scroll through a log and see who reached out, what they asked for, and whether they paid.

- 🧑‍💼 **For node runners:** keep your Lightning Address front door open while the sensitive admin UI stays on your LAN / VPN.
- 🧑‍🎓 **For newcomers:** no need to memorize LNURL specs - lnSwitchboard bakes in the right metadata, comment limits, payer identity rules, and verification endpoints automatically.

---

## Why operators install lnSwitchboard

- **One app, many handles.** Map unlimited usernames, vanity tags, and promo aliases to the same Lightning backend. Per-handle overrides let you tune min/max sats, metadata, and success messages without touching global config.
- **Wallet compatibility out of the box.** Implements the core LNURL LUDs (06/09/12/16/17/18/20/21), NIP-05, and NIP-57 zap receipts for linked local identities, so everything from Alby to Wallet of Satoshi, or Bitcoin Well... “just works.”
- **Actionable visibility.** The built-in dashboard shows 24h/7d request volume, invoices generated vs. paid, sats routed, inbound liquidity, and a searchable activity log with proxy/IP context.
- **Security-first defaults.** Rate limiting (per-IP), macaroon validation, TLS handling, and proxy-aware callback URLs keep the public face minimal while admin routes stay private.
- **Umbrel & Docker native.** Install with one click on Umbrel or run anywhere with Docker/Compose/k8s, mounting LND's data directory read-only for TLS and macaroons.

---

## Feature Highlights

| Area | What you get |
| --- | --- |
| **LNURL Router** | LNURL-pay discovery + invoice endpoints that understand tags, long descriptions, payer data, comments, and lightning-fast verification links. |
| **Dashboard** | Live metrics, trend charts, and a status chip that pings `/api/health` every 10 seconds so you know your node is reachable. |
| **Invoices hub** | Dedicated `/invoices/` page backed by a SQLite `invoice_events` table. Real-time updates come from a gRPC subscription worker plus a periodic full refresh loop. |
| **Request log** | Searchable log of discovery, invoice, verify, webhook delivery, and rate-limit events with metadata previews, payers' comments, and proxy headers for forensic-level visibility. |
| **LN address customization** | Pin custom min/max sats, template text, per-handle payer data, signed webhook automation, and delivery filters to any `local_part@domain`. Tags automatically inherit from the base handle. |
| **NIP-05 + zaps** | Manage Nostr mappings (npub/hex + relay list), serve `/.well-known/nostr.json`, advertise NIP-57 zap support when a local identity has a signer, and publish kind `9735` receipts after settlement. |
| **Webhook observability** | Persist HTTP webhook and Nostr relay delivery attempts, record each attempt in Request Logs, and send signed test payloads from the Webhooks reference. |
| **Env + macaroon management** | Update `.env` safely via the UI, use LND's mounted `invoice.macaroon`, or manually paste/upload a macaroon when no file path is configured. |

---

## Getting Started

### 🚀 Umbrel
1. Open the Umbrel App Store and search for **“lnSwitchboard.”**
2. Click **Install** and wait for Umbrel to launch lnSwitchboard.
3. Open lnSwitchboard from the Umbrel dashboard. Umbrel's authenticated `app_proxy` reaches the administration listener on port `22121`; public connectors use port `21212` directly on the private app network.

Umbrel keeps lnSwitchboard updated automatically, so you always receive the latest features and security fixes.

### 🐳 Docker Compose

The repo ships with a ready-to-edit [`docker-compose.yml`](./docker-compose.yml). Mount LND's data directory read-only, set `LND_HOST`, point `LND_MACAROON_PATH` at the existing LND invoice macaroon, and point `LND_TLS_PATH` at LND's existing `tls.cert`:

```yaml
volumes:
  - ${APP_LIGHTNING_NODE_DATA_DIR}:/lnd:ro
environment:
  DEP_ENV: DOCKER
  LND_TLS_PATH: /lnd/tls.cert
  LND_MACAROON_PATH: /lnd/data/chain/bitcoin/${APP_BITCOIN_NETWORK:-mainnet}/invoice.macaroon
  LND_READONLY_MACAROON_PATH: /lnd/data/chain/bitcoin/${APP_BITCOIN_NETWORK:-mainnet}/readonly.macaroon
```

`DEP_ENV` controls the upstream host shown in the in-app reverse proxy reference. Use `DOCKER` for standalone Compose, `UMBREL` for the Umbrel store app, or `UMBREL-DEV` for the extended Umbrel dev app name.

Then run:

```bash
docker compose up -d
```

The Compose stack includes a dedicated Cloudflare Mesh node pinned to the immutable multi-platform digest for `cloudflare/mesh:2026.7.0`. It publishes no host ports, has no Docker socket, does not use host networking, and is configured to forward customer traffic only to the public application listener. Cloudflare Mesh requires only `/dev/net/tun`, `NET_ADMIN`, `NET_RAW`, and IP-forwarding sysctls. lnSwitchboard writes the node enrollment material under `./secrets/cloudflare-mesh`; the sidecar mounts that directory read-only and forwards public traffic only to the application listener on port `21212`.

Before Cloudflare onboarding is complete, the Mesh sidecar restarts with backoff while waiting for `./secrets/cloudflare-mesh/node.env`; this is expected. The wrapper reads the token without placing it in Compose, a command line, browser storage, or application logs. The Connections page distinguishes an installed Mesh capability from an active Cloudflare connection.

The Compose stack also includes a dedicated Tailscale userspace sidecar, pinned to `tailscale/tailscale:v1.98.10` by immutable multi-platform digest. It uses a private daemon-state volume and a separate named control/status volume shared only with lnSwitchboard. The container has a read-only root filesystem, drops every Linux capability, enables `no-new-privileges`, publishes no host ports, and mounts neither `/dev/net/tun` nor the Docker socket.

The runtime starts in Tailscale's `NeedsLogin` state and waits for lnSwitchboard's authenticated lifecycle controller. Authorization is intentionally absent from Compose: no OAuth client, API token, or reusable auth key is accepted through environment variables. Control is restricted to fixed marker operations, and the only user-derived runtime value is a separately validated single-label device name. Normal onboarding deletes authorization output immediately; a five-minute fallback removes it if the application exits before cleanup.

Funnel is hard-coded to public HTTPS port `443` with the local destination `http://127.0.0.1:21212`. Because the sidecar shares only lnSwitchboard's network namespace, this reaches the public application listener and never exposes the administration listener on `22121`. A tailnet must have MagicDNS and HTTPS certificates enabled, and its policy must grant the node (or a tag chosen by the operator) the `funnel` node attribute. The runtime reports missing prerequisites but never modifies tailnet policy.

Open **Connections → Tailscale** from the administration panel to onboard the node. lnSwitchboard supports HTTP or HTTPS administration; the operator is responsible for choosing and securing the administration path. The form then asks only for a device name and suggests `lns` by default; it does not ask for a public domain, OAuth credential, API token, or reusable auth key. Device names are normalized to lowercase and must be a single 1–63 character DNS label containing only letters, numbers, and internal hyphens.

lnSwitchboard starts Tailscale's interactive browser login and shows its short-lived authorization link and in-memory QR code only inside the private administration flow. The link is never written to application logs, connection metadata, browser storage, or retained query state. After login, lnSwitchboard reads the daemon-owned DNS name, accepts only a canonical `*.ts.net` hostname covered by `CertDomains`, verifies MagicDNS, HTTPS, the `funnel` node attribute, and port `443`, then enables the fixed Funnel target. Missing prerequisites remain visible for manual correction; lnSwitchboard never edits broad tailnet policy. Cancellation, expiry, failed validation, successful connection, restart recovery, and disconnect all remove transient authorization artifacts.

Open **Connections → Cloudflare** to onboard a hostname through Cloudflare OAuth. There is no manual API-token path and no OAuth client secret. Authorization uses PKCE S256 directly between the local lnSwitchboard instance and Cloudflare; access and refresh grants are encrypted in the local connection secret store and are never returned to the browser after exchange.

The project OAuth application is a public client (`token_endpoint_auth_method: none`). Register it with these exact Cloudflare OAuth scope IDs, which were verified against the authenticated `GET /client/v4/oauth/scopes` catalog:

- `account-settings.read` — Account Settings Read
- `zone.read` — Zone Read
- `dns.read`, `dns.write` — DNS Read/Write
- `workers-scripts.read`, `workers-scripts.write`, `workers-scripts.bind` — Worker source and the `vpc_network` binding
- `connectivity-directory.bind` — authorize the Worker VPC binding to Cloudflare's connectivity directory
- `workers-routes.read`, `workers-routes.write` — path-specific Workers Routes
- `teams-connector-warp.read`, `teams-connector-warp.write` — Mesh/WARP connector lifecycle
- `teams.read`, `teams.write` — Cloudflare One device and Gateway prerequisites
- `access.read`, `access.write` — Access enrollment application and policy prerequisites
- `offline_access` — local refresh-token support

Configure the same space-separated list in `CLOUDFLARE_OAUTH_SCOPE`. The setup API keeps onboarding disabled until a non-placeholder client ID and callback page are configured.

Register both exact redirect URIs: `http://127.0.0.1:22121/api/cloudflare/oauth/callback` for direct loopback completion and the HTTPS URL where `oauth-callback/index.html` is hosted for paste-back completion. The static callback uses fragment delivery, a hash-restricted CSP, no analytics or external resources, and no network requests. Configure `CLOUDFLARE_OAUTH_CLIENT_ID` and `CLOUDFLARE_OAUTH_REDIRECT_PAGE`. Never configure or ship a client secret.

After consent, choose an OAuth-authorized account and zone rather than pasting resource IDs. lnSwitchboard idempotently verifies or configures the Cloudflare One prerequisites needed by Mesh: device enrollment, the default Split Tunnels profile, Gateway TCP/UDP proxying, unique device IPs, and Mesh connectivity. Customized settings that cannot be changed safely are reported for operator action instead of being overwritten.

lnSwitchboard creates the Mesh node and its exact `lns.internal` hostname route, deploys `lnswitchboard-proxy` into the customer's own Cloudflare account with a `vpc_network` binding, and installs exactly two Workers Routes per hostname: `HOST/.well-known/lnurlp/*` and `HOST/.well-known/nostr.json`. The Worker has no logs, telemetry, analytics bindings, or external fetch path; it only forwards to `env.MESH.fetch()` and returns a fixed sanitized `503` on failure. Public traffic therefore flows from Cloudflare directly through resources in the customer's account to the customer's local Mesh and port `21212`; no project-operated service is in the data path.

Existing usable DNS is preserved. If Cloudflare requires a proxied record and none exists, lnSwitchboard creates an explicitly owned placeholder and deletes it only after immediate ownership revalidation. Identical Workers Routes owned by another script are conflicts; routes already assigned to `lnswitchboard-proxy` are adopted idempotently. Each hostname can be removed independently, while full disconnect removes only resources whose exact ownership is revalidated.

Compose binds administration port `22121` to loopback by default and publishes public port `21212` for LNURL-pay and NIP-05 traffic. The administration listener allows direct loopback/RFC1918 LAN clients (plus IPv6 ULA/link-local clients) and returns `403` to WAN peers. Provider onboarding follows the same administration policy; it does not impose a stricter HTTPS or proxy-identity condition. Override `LNSWITCHBOARD_BIND_ADDRESS` only when the administration listener must bind another host interface.

Requests on port `21212` use the direct `Host` value, the fixed public-host header supplied by the customer-owned Worker, or forwarding headers from peers listed in `TRUSTED_PROXY_CIDRS`. The resolved domain must match a configured Lightning Address, Nostr identity, or a pending/active provider domain registered by Cloudflare or Tailscale Funnel; otherwise the public listener returns `404`.

Set `TRUSTED_HOSTS` to every hostname that may serve lnSwitchboard (comma-separated; `*.example.com` wildcards are supported). Requests with any other `Host` value are rejected, which protects a loopback deployment from DNS rebinding. Forwarding headers are ignored unless the immediate reverse proxy is explicitly listed in `TRUSTED_PROXY_CIDRS` (comma-separated IPs or CIDR ranges). Configure the narrowest possible proxy network so LNURL callback URLs and client rate limits use the original HTTPS request safely; never trust an entire shared LAN. Outbound webhooks and Nostr zap receipts refuse destinations on private, loopback, link-local, or reserved networks by default; enable `ALLOW_PRIVATE_WEBHOOKS` or `ALLOW_PRIVATE_NOSTR_RELAYS` only when intentionally targeting trusted local services.

### 🧩 Manual (bare metal)

The supported toolchain is Python 3.11 or newer and Node.js 22.22.2 or newer. CI, release images, `.python-version`, and `.nvmrc` currently pin Python 3.14.6 and Node.js 26.5.1.

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd frontend && npm ci && npm run build && cd ..
.venv/bin/python -m backend.app.server
```

Set `LND_TLS_PATH`, `LND_MACAROON_PATH`, and `LND_READONLY_MACAROON_PATH` to existing LND files before launching. lnSwitchboard uses `invoice.macaroon` for invoice creation/lookup/subscription and `readonly.macaroon` for liquidity reads such as `ListChannels`. By default, lnSwitchboard verifies LND's certificate against `LND_HOST` using the trust roots from `LND_TLS_PATH`; set `LND_TLS_SERVER_NAME` only when you intentionally need to verify against a different certificate SAN. If `LND_MACAROON_PATH` is not set, open Settings and paste a hex macaroon or upload a binary `invoice.macaroon`; lnSwitchboard stores the manual fallback as hex at `MACAROON_STORE_PATH`. Environment settings saved through the dashboard are persisted to `.env` and apply after lnSwitchboard restarts.

### 🛠️ LND Diagnostics

The Docker image includes a read-only support script that checks LND env wiring, mounted macaroon files, TLS certificate names, gRPC TLS readiness, and basic RPC permissions without printing macaroon contents:

```bash
docker exec <lnswitchboard-container> lnswitchboard-diagnose-lnd
```

---

## How it Works (Under the Hood)

1. **FastAPI core** mounts the static frontend and exposes LNURL, UI, identity, and LN-address routers. The UI and admin API stay same-origin; only the explicitly documented public endpoints should be internet-facing.
2. **LN client** (`grpc.aio`) talks to LND using your TLS cert + invoice macaroon, generating invoices with properly hashed metadata and watching channel capacity to set `maxSendable`.
3. **LN address store** lives in SQLite, so per-handle overrides survive restarts and apply to every `user+tag`.
4. **Request log storage** mirrors all discovery/invoice/verify events in SQLite plus an in-memory deque for fast UI reads. Older entries age out via `LOG_RETENTION_DAYS`.
5. **Invoice workers**:
   - `InvoiceSubscriptionWorker` listens to `SubscribeInvoices` and updates settlement state instantly.
   - `InvoiceFullRefreshWorker` sweeps pending invoices on a fixed interval so nothing slips through.
6. **Rate limiter + proxy awareness** ensure only legitimate traffic hits LND while callback URLs honor `Forwarded` / `X-Forwarded-*` headers so wallets see the same host you advertise.

---

## UI Walkthrough

- **Dashboard:** Lightning snapshot, 24h/7d request counts, invoices minted/paid, sats routed, and a 14-day chart of settled activity.
- **Invoices:** Paginated table with per-invoice modals showing hashes, sats, expiry, and settle timestamps.
- **Liquidity:** Channel table (peer alias, Amboss links, local/remote balances) plus the largest receivable metric powered by `list_channels`.
- **Logs:** Filterable event log with modal JSON viewer - perfect for debugging wallet interactions.
- **LN Addresses:** Create/edit/delete overrides with validation, variable hints, Nostr identity badges, payer-data schemas, signed webhook filters, and webhook badges when automations are attached to a handle.
- **Identities:** CRUD for `local_part@domain` → `npub` mappings plus relay lists.
- **Settings:** Mounted macaroon status, manual macaroon paste/upload fallback, Nostr zap signer generation/import, `.env` editor with grouped hints, and a reverse-proxy snippet you can copy into Nginx/Caddy.
- **Webhooks:** Request-log delivery events, test sends, signed receiver headers, forwarded-invoice caveats, and payload reference material.

Screenshots coming soon - until then, install on Umbrel or fire up the Docker image to explore the dashboard, request logs, signer controls, and address automation tools in minutes.

---

## Supported Specs

- [LUD-06 · `payRequest` base spec](https://github.com/lnurl/luds/blob/luds/06.md)
- [LUD-09 · `successAction`](https://github.com/lnurl/luds/blob/luds/09.md)
- [LUD-12 · Payer comments](https://github.com/lnurl/luds/blob/luds/12.md)
- [LUD-16 · Lightning Addresses](https://github.com/lnurl/luds/blob/luds/16.md)
- [LUD-17 · Protocol schemes](https://github.com/lnurl/luds/blob/luds/17.md)
- [LUD-18 · Payer identity](https://github.com/lnurl/luds/blob/luds/18.md)
- [LUD-20 · Long descriptions](https://github.com/lnurl/luds/blob/luds/20.md)
- [LUD-21 · Verify endpoint](https://github.com/lnurl/luds/blob/luds/21.md)
- [NIP-05 · Nostr identities](https://github.com/nostr-protocol/nips/blob/master/05.md)
- [NIP-57 · Lightning zaps](https://github.com/nostr-protocol/nips/blob/master/57.md)

---

## Docs, Support & Contributing

- 📚 **Documentation:** Check the app's **References** section for quick how-to guides.
- 📦 **Docker packages:** [`ryleastark/lnswitchboard`](https://hub.docker.com/r/ryleastark/lnswitchboard) and [`ghcr.io/ryleastark/lnswitchboard`](https://github.com/RyleaStark/lnSwitchboard/pkgs/container/lnswitchboard).
- 🐛 **Issues & feature requests:** Open a ticket on [GitHub Issues](https://github.com/RyleaStark/lnSwitchboard/issues).
- ⚡ **Tips:** Send sats to `tips+ln@bigbones.net` to keep the project zapping.

Pull requests are welcome - please read the wiki, run the test suite (`.venv/bin/python -m pytest`), and describe your changes clearly so we can review quickly.

---

## License & Credits

Copyright © [Rylea Stark](https://github.com/RyleaStark). All rights reserved unless otherwise noted.
