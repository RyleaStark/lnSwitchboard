# lnSwitchboard <img align="right" width="120" src="https://raw.githubusercontent.com/RyleaStark/lnSwitchboard/a45b43937326e87e1a01a035182dfe174310a79e/frontend/static/icon.svg" alt="lnSwitchboard logo" />

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
- **Umbrel & Docker native.** Install with one click on Umbrel or run anywhere with Docker/Compose/k8s, mounting your `secrets/` folder for TLS + macaroons.

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
| **Env + macaroon management** | Update `.env` safely via the UI, rotate invoice macaroons, and apply changes without restarting the container. |

---

## Getting Started

### 🚀 Umbrel
1. Open the Umbrel App Store and search for **“lnSwitchboard.”**
2. Click **Install** and wait for Umbrel to launch the container on port `22121`.
3. Visit `http://umbrel.local:22121/` (or your Umbrel’s IP), paste your invoice macaroon, and follow the sidebar instructions to point `/.well-known/lnurlp/` at the service.

Umbrel keeps lnSwitchboard updated automatically, so you always receive the latest features and security fixes.

### 🐳 Docker Compose

The repo ships with a ready-to-edit [`docker-compose.yml`](./docker-compose.yml). Mount `secrets/`, set `LND_HOST`, then run:

```bash
docker compose up -d
```

Once the service is running, point your reverse proxy so that only `/.well-known/lnurlp/*` and `/.well-known/nostr.json` hit port `22121`. Keep the dashboard behind a VPN, SSH tunnel, or HTTP auth.

### 🧩 Manual (bare metal)

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 22121
```

Populate `secrets/tls.cert`, `secrets/macaroon.hex`, and (optionally) `.env` before launching.

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
- **Settings:** Macaroon upload/rotation, `.env` editor with grouped hints, and a reverse-proxy snippet you can copy into Nginx/Caddy.

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

- 📚 **Documentation:** [lnSwitchboard Wiki](https://github.com/RyleaStark/lnSwitchboard/wiki) (architecture, API reference, setup guides).
- 📦 **Docker package:** [`ghcr.io/RyleaStark/lnswitchboard`](https://github.com/RyleaStark/lnSwitchboard/pkgs/container/lnswitchboard).
- 🐛 **Issues & feature requests:** Open a ticket on [GitHub Issues](https://github.com/RyleaStark/lnSwitchboard/issues).
- ⚡ **Tips:** Send sats to `lnswitchboard+tips@bigbones.net` to keep the project zapping.

Pull requests are welcome - please read the wiki, run the test suite (`.venv/bin/python -m pytest`), and describe your changes clearly so we can review quickly.

---

## License & Credits

Copyright © [Rylea Stark](https://github.com/RyleaStark). All rights reserved unless otherwise noted.
