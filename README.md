# lnSwitchboard <img align="right" width="120" src="https://raw.githubusercontent.com/RyleaStark/lnSwitchboard/06b3a888fe95d4f07653651edba6c99d0bda0b3d/frontend/static/icon.svg" alt="lnSwitchboard logo" />

**Turns any Lightning node into a sovereign Lightning Address switchboard that speaks LNURL, watches your liquidity, and lets you manage identities without touching the command line.**

Published on the [Umbrel App Store](https://umbrel.com/), shipped as a public [Docker package](https://github.com/RyleaStark/lnSwitchboard/pkgs/container/lnswitchboard), and fully documented in the [project wiki](https://github.com/RyleaStark/lnSwitchboard/wiki).

---

## What is lnSwitchboard? (ELI5)

Think of your Lightning node as a call center. Every time someone zaps `yourname@yourdomain`, a little switchboard operator (lnSwitchboard) picks up, checks who’s calling, makes sure the line isn’t being spammed, and then patches the call through with a freshly minted invoice. The operator keeps notes about every call, so you can later scroll through a log and see who reached out, what they asked for, and whether they paid.

- 🧑‍💼 **For node runners:** keep your Lightning Address front door open while the sensitive admin UI stays on your LAN / VPN.
- 🧑‍🎓 **For newcomers:** no need to memorize LNURL specs - lnSwitchboard bakes in the right metadata, comment limits, payer identity rules, and verification endpoints automatically.

---

## Why operators install lnSwitchboard

- **One app, many handles.** Map unlimited usernames, vanity tags, and promo aliases to the same Lightning backend. Per-handle overrides let you tune min/max sats, metadata, and success messages without touching global config.
- **Wallet compatibility out of the box.** Implements the core LNURL LUDs (06/09/12/16/17/18/20/21) plus NIP-05, so everything from Alby to Wallet of Satoshi, or Bitcoin Well... “just works.”
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
| **Request log** | Searchable log of discovery, invoice, verify, and rate-limit events with metadata previews, payers’ comments, and proxy headers for forensic-level visibility. |
| **LN address customization** | Pin custom min/max sats, template text, and multi-webhook automations to any `local_part@domain`. Tags automatically inherit from the base handle. |
| **NIP-05 identities** | Manage Nostr mappings (npub/hex + relay list) from the UI, and serve `/.well-known/nostr.json` with proper CORS. |
| **Env + macaroon management** | Update `.env` safely via the UI, use LND's mounted `invoice.macaroon`, or manually paste/upload a macaroon when no file path is configured. |

---

## Getting Started

### 🚀 Umbrel
1. Open the Umbrel App Store and search for **“lnSwitchboard.”**
2. Click **Install** and wait for Umbrel to launch the container on port `22121`.
3. Visit `http://umbrel.local:22121/` (or your Umbrel’s IP) and follow the proxy instructions to point `/.well-known/lnurlp/` at the service.

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

Once the service is running, point your reverse proxy so that only `/.well-known/lnurlp/*` and `/.well-known/nostr.json` hit port `22121`. Keep the dashboard behind a VPN, SSH tunnel, or HTTP auth.

### 🧩 Manual (bare metal)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd frontend && npm ci && npm run build && cd ..
.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 22121
```

Set `LND_TLS_PATH`, `LND_MACAROON_PATH`, and `LND_READONLY_MACAROON_PATH` to existing LND files before launching. lnSwitchboard uses `invoice.macaroon` for invoice creation/lookup/subscription and `readonly.macaroon` for liquidity reads such as `ListChannels`. By default, lnSwitchboard verifies LND's certificate against `LND_HOST` using the trust roots from `LND_TLS_PATH`; set `LND_TLS_SERVER_NAME` only when you intentionally need to verify against a different certificate SAN. If `LND_MACAROON_PATH` is not set, open Settings and paste a hex macaroon or upload a binary `invoice.macaroon`; lnSwitchboard stores the manual fallback as hex at `MACAROON_STORE_PATH`.

### 🛠️ LND Diagnostics

The Docker image includes a read-only support script that checks LND env wiring, mounted macaroon files, TLS certificate names, gRPC TLS readiness, and basic RPC permissions without printing macaroon contents:

```bash
docker exec <lnswitchboard-container> lnswitchboard-diagnose-lnd
```

---

## How it Works (Under the Hood)

1. **FastAPI core** mounts the static frontend and exposes LNURL, UI, identity, and LN-address routers. CORS is limited to `GET` since only public endpoints should be internet-facing.
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
- **LN Addresses:** Create/edit/delete overrides with validation, variable hints, Nostr identity badges, and webhook badges when automations are attached to a handle.
- **Identities:** CRUD for `local_part@domain` → `npub` mappings plus relay lists.
- **Settings:** Mounted macaroon status, manual macaroon paste/upload fallback, `.env` editor with grouped hints, and a reverse-proxy snippet you can copy into Nginx/Caddy.

Screenshots coming soon - until then, install on Umbrel or fire up the Docker image to explore in minutes.

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

---

## Docs, Support & Contributing

- 📚 **Documentation:** Check the app's **References** section for quick how-to guides.
- 📦 **Docker package:** [`ghcr.io/RyleaStark/lnswitchboard`](https://github.com/RyleaStark/lnSwitchboard/pkgs/container/lnswitchboard).
- 🐛 **Issues & feature requests:** Open a ticket on [GitHub Issues](https://github.com/RyleaStark/lnSwitchboard/issues).
- ⚡ **Tips:** Send sats to `tips+ln@bigbones.net` to keep the project zapping.

Pull requests are welcome - please read the wiki, run the test suite (`.venv/bin/python -m pytest`), and describe your changes clearly so we can review quickly.

---

## License & Credits

Copyright © [Rylea Stark](https://github.com/RyleaStark). All rights reserved unless otherwise noted.
