# Private scoped integration API

This API is mounted on the private administration listener and, when enabled, an additional **client-only LAN listener**. It is not on the public listener, public gateway or Cloudflare route allowlist. Restrict both private listeners to trusted hosts. Use a private VPN or TLS-protected transport: a bearer token does not encrypt HTTP. Existing administration endpoints retain their network-trusted operator security model; do not publicly expose them.

For machine clients that cannot use the dashboard login proxy, set `CLIENT_API_ENABLED=true`, `CLIENT_API_HOST` to the intended bind address (default `127.0.0.1`), and `CLIENT_API_PORT` (default `22122`). This listener serves only `/api/client/v1/`; credential provisioning, settings, dashboard, health and public LNURL routes return 404. It retains the private-client IP guard and mandatory bearer checks and disables Uvicorn proxy-header trust. The Umbrel package binds it inside the app container and publishes port 22122; the dashboard remains behind Umbrel login on 22121. Do not forward 22122 to the Internet. HTTP on a trusted LAN is unencrypted; use private encrypted transport when that is insufficient.

## Operator provisioning

`POST /api/client-credentials` accepts exactly:

```json
{"domain":"pay.example.com","webhook_url":"https://billing.example.com/bridge","webhook_secret":"operator-generated-at-least-32-characters","scopes":["addresses:create","addresses:read_own","invoices:create"]}
```

The domain must already be routed/configured by the operator for public LNURL use; provisioning a credential does not configure DNS, tunnels or providers. HTTP bridge URLs require the explicit existing `ALLOW_PRIVATE_WEBHOOKS` setting. Delivery retains existing webhook destination checks. Clients cannot supply their own bridge URL or secret.

The 201 response contains `client_id`, `token`, `domain`, `scopes`. Save the token securely immediately; it is returned once and stored only as a SHA-256 hash. The fixed bridge configuration is encrypted by the existing connection-secret store. `GET /api/client-credentials` returns safe client metadata, never keys or bridge secrets. `DELETE /api/client-credentials/{client_id}` returns 204 and revokes the credential. Revocation blocks future requests but cannot cancel an RPC already accepted by LND, invalidate an issued invoice or undo a payment. Address/webhook records remain to track outstanding payments.

These are explicit operator endpoints, not client scopes. Open **Settings → Machine clients** in the authenticated dashboard to provision, list and revoke clients. The token is shown once, held only in component memory and cleared when dismissed or when leaving the tab; signing-secret inputs clear on submission (including failure) and cancellation. Save tokens in a secret manager; copying uses the system clipboard, which you must clear separately. Never place keys in URLs, logs or screenshots. Client responses, validation errors and administration responses use `Cache-Control: no-store, private`.

### Operator listener status (additive)

`GET /api/client-credentials/status` is administration-only and no-store. It returns exactly `enabled` (boolean), `listening` (boolean), `host` (string), `port` (integer), and `allow_private_webhooks` (boolean). Listening is based on the in-process Uvicorn server being started and its task still running, not configuration alone; it does not establish Docker host publication, firewall admission or remote reachability. Unknown/unavailable status must not be treated as ready. All existing credential and client request/response schemas and webhook contracts remain unchanged.

The existing optional `ALLOW_PRIVATE_WEBHOOKS` opt-in is now available under **Settings → Environment → Security → Allow private webhooks**. It remains disabled by default and applies to all webhook delivery. Enabling it permits HTTP/private destinations; restart to apply. Do not enable it for ordinary public HTTPS receivers. Settlement proof is automatic; no new proof toggle or global fixed-invoice expiry setting is introduced. Authorized clients still choose amount and 14/30-day expiry per request.

### Adopt an existing address (operator only)

`POST /api/client-credentials/{client_id}/addresses/adopt` is available **only on the private administration listener**, under the same network-trusted operator access control as credential provisioning. It is not a bearer-token permission, not mounted on the client-only listener or public listener, and requires no new client scope. The operator sends exactly:

```json
{"address_id":"e755de8b-943a-40ce-8a12-975d6d61dcef","external_user_ref":"opaque-random-user-000012"}
```

`address_id` must be a canonical lowercase hyphenated UUID of an already-existing address; `external_user_ref` follows the same 16–128-character opaque syntax as client allocation. Use a random identifier, never an email or user name. The path client must exist, remain active, and have the address's exact domain; the address must be locally routed. The address cannot already belong to another client, or to this client under a different reference; a reference cannot already identify another address. A repeat of the identical adoption returns the same 201 body, even without an idempotency key. Missing client/address returns 404; revoked client, domain/routing mismatch and ownership/reference conflicts return 409; invalid body returns 422. The response is `Cache-Control: no-store, private` and contains exactly `address_id` and `ln_address`, matching ordinary address GET.

Only a binding in `api_owned_addresses` is added transactionally; adoption does not allocate or modify the LN address, webhook destinations/secrets, invoice records or settlement/replay history. The operator performs adoption **first**; the Silo machine token then verifies with `GET /api/client/v1/addresses/{address_id}?user_ref_hash=<sha256-hex>` using its existing `addresses:read_own` scope and checks the returned UUID and LN address. Compute the hash from the exact opaque `external_user_ref` used for adoption (see below); this verifies the per-account binding as well as machine ownership. Neither Silo nor another client must call an adoption/grant endpoint. Existing `POST /api/client/v1/addresses` allocation behavior and its idempotency key remain unchanged. This contract does not migrate any live address or change a deployed installation by itself.

## Client requests

Every `/api/client/v1` request requires `Authorization: Bearer <token>`, including LAN requests. Missing, malformed, unknown and revoked credentials return 401. Missing scopes return 403. Foreign and missing address IDs both return 404.

### Allocate/read an address

`POST /api/client/v1/addresses` requires `addresses:create`, an `Idempotency-Key`, and:

```json
{"external_user_ref":"opaque-random-user-000001"}
```

The reference must be 16–128 ASCII letters, numbers, `_` or `-`; use a random opaque identifier, never email, name or provider identity. Only its hash is stored. Response 201:

```json
{"address_id":"<uuid>","ln_address":"pay-<random>@pay.example.com"}
```

Routing and bridge configuration are operator-fixed. `GET /api/client/v1/addresses/{address_id}` requires `addresses:read_own` and returns the same two safe address fields. Optionally send `user_ref_hash` as a query parameter containing exactly 64 lowercase hexadecimal characters: the SHA-256 of the UTF-8 bytes of the exact opaque `external_user_ref` used to create or adopt the address. When present it must match that client's stored `api_owned_addresses.user_ref_hash` for this address; wrong, malformed, foreign or missing bindings return the same generic 404. Omission preserves the existing machine-owned address lookup. The query does not mutate address or ownership state and never adds fields to the response. Send the hash, **not the raw reference**, and protect request URLs in logs; this endpoint is private and its response is `Cache-Control: no-store, private`.

### Fixed invoice

`POST /api/client/v1/addresses/{address_id}/invoices` requires `invoices:create`, ownership, an `Idempotency-Key`, and:

```json
{"quote_id":"opaque-quote-000001","amount_msat":2000,"expiry_days":14}
```

`quote_id` is 1–128 ASCII letters, numbers, `_` or `-`; it must not contain personal information. `amount_msat` is a strict positive integer no greater than 9007199254740991 and must also satisfy configured global/address limits. `expiry_days` is the exact JSON integer 14 or 30. Unknown fields and coercions are rejected. Ordinary LNURL expiry defaults are unchanged.

The 201 response has exactly `address_id`, `quote_id`, `amount_msat`, `payment_hash` (lowercase hex), `bolt11`, `created_at` and `expires_at`. Both dates are Unix integer seconds, derived from LND's authoritative `creation_date` and explicit expiry, not the API clock. Store the exact hash/address/quote binding before presenting the invoice.

### Authoritative invoice settlement lookup (additive)

`GET /api/client/v1/addresses/{address_id}/invoices/{payment_hash}` requires the existing **`invoices:create`** bearer scope; no credential rotation or new scope is needed. No request body or idempotency key is required. The hash must be exactly 64 lowercase hexadecimal characters. The address must remain owned by this client, unchanged on its operator-fixed domain, and locally routed. Only a completed, recorded fixed client invoice with the exact client/address/quote/request fingerprint and operational binding can be read; unrelated LNURL, foreign, unbound and incomplete invoices cannot be queried.

A successful response contains **exactly** these keys (example values are synthetic):

```json
{"payment_hash":"<64-lowercase-hex>","address_id":"<uuid>","ln_address":"pay-<random>@pay.example.com","client_id":"<uuid>","quote_id":"opaque-quote-000001","amount_msat":2000,"created_at":1790000000,"expires_at":1791209600,"settled":true,"paid_msat":2500,"settled_at":1790000100}
```

Amounts are strict JSON integer millisatoshis; timestamps are strict integer UTC Unix seconds. Each read performs a bounded LND `LookupInvoice` for this exact hash, verifying face amount, creation date and expiry against the issued record. `paid_msat` is actual LND `amt_paid_msat`, not face value or a sats conversion. `settled_at` is actual LND `settle_date`, not webhook observation time or API time. A valid open/accepted invoice returns `settled: false`, `paid_msat: 0`, `settled_at: 0`. A settled invoice must have state SETTLED, strict settled true, positive safe-integer paid evidence and a valid settlement date. Canceled invoices return 409; inconsistent/malformed snapshots, unavailable/missing LND invoices and RPC failures/timeouts return generic 503, never a paid assertion. Missing/foreign/unbound invoices return 404; revoked credentials return 401, including revocation observed after lookup. The response is `Cache-Control: no-store, private` and contains no preimage, BOLT11, HTLCs, payer data or secrets. GET never calls AddInvoice, claims a lease, or writes invoice/recovery state.

LAN Billing may accept an unsigned raw notification as an **untrusted wake-up hint** and then perform this authenticated private lookup; this does not require a receiver container or signature headers. The operator-fixed `webhook_url` may target the native Silo direct-callback endpoint instead of a bridge. An existing integration keeps the same client/address IDs, bearer token and scopes; do not re-provision or revoke it for this additive API. After installing and verifying lookup, the operator can update the encrypted client callback URL and the owned address's webhook endpoints together through supported internal/native stores. This release does not change live routing. Never credit from the hint alone. Match the returned hash, address, LN address, client, quote, fixed amount and dates to the stored quote; require `settled === true` and `paid_msat >=` the expected face amount. Credit one period exactly once using durable invoice/quote deduplication; overpayment earns no extra periods. On lookup failure remain pending and retry the lookup. Existing signed-webhook behavior is unchanged for consumers that use it. This private endpoint remains excluded from all public routes.

## Idempotency, recovery and retention

Keys are 8–128 ASCII letters, numbers, `_` or `-`, scoped to the credential across operation types. Repeat the same key and body to recover the original result. Changed body/operation returns 409. A concurrent leased operation returns 409 with `Retry-After: 2`. Reusing a logical user reference or quote under a different key returns 409; keep the original key. A quote identifies one invoice per credential, across addresses.

Before `AddInvoice`, persist the request fingerprint, chosen random preimage (encrypted), fixed payment hash, ownership and operational invoice event. Every attempt first looks up that exact hash; a lost AddInvoice response can therefore be recovered without allocating another invoice. LND duplicate-hash rejection is an additional guard. RPC timeout/outcome uncertainty returns generic 503: retry the **same key/body**, never allocate a replacement merely because of a timeout. An unrecoverable secret-store failure requires operator intervention, not a new guessed payment hash.

Leases are fenced on completion and release. An active RPC already sent cannot be recalled by lease expiry or credential revocation. A planned event is registered before AddInvoice so immediate settlement is not lost; a poll that races ahead of AddInvoice leaves it pending. Unreconciled client invoice events survive history retention even after wall-clock expiry, so a restart can query LND before declaring a payment expired. Settled proof is retained from observation time and while its delivery/replay record remains. A transactionally persisted settlement outbox closes the crash gap between recording payment and queuing its webhook; startup and full-refresh recovery drain that obligation. Delivery remains **at least once**, so consumers must deduplicate by invoice hash/quote. Public LNURL verification is bound to tracked LNURL username/domain and excludes fixed client invoices entirely; preimages are never returned for an unsettled invoice. Durable client/request/ownership records and encrypted recovery material are not aged out by history cleanup: deleting these manually breaks recovery guarantees. Back up the private database **and** existing encryption-key material together. Never copy decrypted preimages into diagnostics.

## Signed settlement binding

Existing outer webhook `version: "1"`, invoice face `amount_msat` and observation-time `settled_at` semantics are unchanged. Authoritative paid evidence uses the additive [`settlement_proof`](settlement-evidence.md). For a locally settled fixed client invoice, the same HMAC-signed body additionally includes:

```json
{"invoice_binding":{"version":1,"client_id":"<uuid>","address_id":"<uuid>","quote_id":"opaque-quote-000001"}}
```

Only these four binding fields are projected from persisted operational metadata. Binding requires valid local settlement proof and matching address ownership metadata. Remote, forwarded, historical-without-evidence and custom test events cannot gain a paid claim. Test deliveries strip both proof and binding. Retry/restart/manual replay rebuild the same signed business payload from persisted evidence.

Consumers must verify the existing HMAC over the **entire** body, then match exact invoice hash, address and quote. Require authoritative actual `amount_paid_msat >=` the expected fixed face amount. Credit one period idempotently; overpayment does not earn another period. There is no ±10% matching rule. Proof carries no preimage, HTLC details or payer identity.

## Verification boundary

Synthetic tests exercise authentication/revocation, scopes, private/public listener isolation, non-reflecting errors, strict expiry, timeout recovery, pre-RPC encrypted persistence, lease fencing, retention, signed settlement and replay. These tests do not send funds or establish production LND/provider readiness. Release publication requires full local/hosted gates and security review; documentation alone is not evidence of a published build.
