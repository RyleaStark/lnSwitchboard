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

These are explicit operator endpoints, not client scopes. Operator provisioning is currently API-only. Never place keys in URLs, logs or screenshots. Client responses, validation errors and administration responses use `Cache-Control: no-store, private`.

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

Routing and bridge configuration are operator-fixed. `GET /api/client/v1/addresses/{address_id}` requires `addresses:read_own` and returns the same safe address fields.

### Fixed invoice

`POST /api/client/v1/addresses/{address_id}/invoices` requires `invoices:create`, ownership, an `Idempotency-Key`, and:

```json
{"quote_id":"opaque-quote-000001","amount_msat":2000,"expiry_days":14}
```

`quote_id` is 1–128 ASCII letters, numbers, `_` or `-`; it must not contain personal information. `amount_msat` is a strict positive integer no greater than 9007199254740991 and must also satisfy configured global/address limits. `expiry_days` is the exact JSON integer 14 or 30. Unknown fields and coercions are rejected. Ordinary LNURL expiry defaults are unchanged.

The 201 response has exactly `address_id`, `quote_id`, `amount_msat`, `payment_hash` (lowercase hex), `bolt11`, `created_at` and `expires_at`. Both dates are Unix integer seconds, derived from LND's authoritative `creation_date` and explicit expiry, not the API clock. Store the exact hash/address/quote binding before presenting the invoice.

## Idempotency, recovery and retention

Keys are 8–128 ASCII letters, numbers, `_` or `-`, scoped to the credential across operation types. Repeat the same key and body to recover the original result. Changed body/operation returns 409. A concurrent leased operation returns 409 with `Retry-After: 2`. Reusing a logical user reference or quote under a different key returns 409; keep the original key. A quote identifies one invoice per credential, across addresses.

Before `AddInvoice`, persist the request fingerprint, chosen random preimage (encrypted), fixed payment hash, ownership and operational invoice event. Every attempt first looks up that exact hash; a lost AddInvoice response can therefore be recovered without allocating another invoice. LND duplicate-hash rejection is an additional guard. RPC timeout/outcome uncertainty returns generic 503: retry the **same key/body**, never allocate a replacement merely because of a timeout. An unrecoverable secret-store failure requires operator intervention, not a new guessed payment hash.

Leases are fenced on completion and release. An active RPC already sent cannot be recalled by lease expiry or credential revocation. A planned event is registered before AddInvoice so immediate settlement is not lost; a poll that races ahead of AddInvoice leaves it pending. Unsettled, unexpired client invoice events survive shorter configured history retention once their expiry is known. Durable client/request/ownership records and encrypted recovery material are not aged out by history cleanup: deleting these manually breaks recovery guarantees. Back up the private database **and** existing encryption-key material together. Never copy decrypted preimages into diagnostics.

## Signed settlement binding

Existing outer webhook `version: "1"`, invoice face `amount_msat` and observation-time `settled_at` semantics are unchanged. Authoritative paid evidence uses the additive [`settlement_proof`](settlement-evidence.md). For a locally settled fixed client invoice, the same HMAC-signed body additionally includes:

```json
{"invoice_binding":{"version":1,"client_id":"<uuid>","address_id":"<uuid>","quote_id":"opaque-quote-000001"}}
```

Only these four binding fields are projected from persisted operational metadata. Binding requires valid local settlement proof and matching address ownership metadata. Remote, forwarded, historical-without-evidence and custom test events cannot gain a paid claim. Test deliveries strip both proof and binding. Retry/restart/manual replay rebuild the same signed business payload from persisted evidence.

Consumers must verify the existing HMAC over the **entire** body, then match exact invoice hash, address and quote. Require authoritative actual `amount_paid_msat >=` the expected fixed face amount. Credit one period idempotently; overpayment does not earn another period. There is no ±10% matching rule. Proof carries no preimage, HTLC details or payer identity.

## Verification boundary

Synthetic tests exercise authentication/revocation, scopes, private/public listener isolation, non-reflecting errors, strict expiry, timeout recovery, pre-RPC encrypted persistence, lease fencing, retention, signed settlement and replay. These tests do not send funds or establish production LND/provider readiness. Release publication requires full local/hosted gates and security review; documentation alone is not evidence of a published build.
