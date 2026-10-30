# Signed local settlement evidence

The `payment.settled` event keeps its existing top-level schema `version: "1"`.
An additive `settlement_proof` object is present **only** for validated local LND
settlement evidence:

```json
{
  "settlement_proof": {
    "version": 1,
    "settlement_source": "local_lnd",
    "amount_paid_msat": 2200,
    "settle_date": 1790000000
  }
}
```

The exact required fields are:

| Field | Meaning and bounds |
| --- | --- |
| `version` | Integer `1`, not the outer event's string version. |
| `settlement_source` | Literal `"local_lnd"`: observed through this operator's configured LND connection, not a remote LNURL verifier. |
| `amount_paid_msat` | Actual `Invoice.amt_paid_msat`, positive integer at most `9007199254740991` (JSON safe-integer limit). Never the invoice face value or a conversion from sats. |
| `settle_date` | Actual `Invoice.settle_date`, Unix seconds, positive integer at most `253402300799` (end of year 9999). Never the worker's clock. |

Proof generation requires both `Invoice.state == SETTLED` and `settled == true`
from the local LND snapshot. The normalized evidence accepts integers only, not
booleans, strings, floats, zero, negative or out-of-range values. No optional
fields are currently defined. No preimage, raw HTLC, payer data, or provider
response is included in the proof. Out-of-range/missing fields omit the proof;
they do not prevent the existing v1 settlement notification.

The worker stores the validated object at
`invoice_events.details.invoice.settlement_proof` **before** webhook enqueue or
send. Polling and subscription share this path. Persistent retries, process
restart and manual replay read the saved evidence and project only the four
allowlisted fields. Reconstruction validates the saved proof and settled state
again. This is an additive operational JSON change, not a database migration.

The existing HMAC signs the complete canonical JSON body, including this nested
object: `timestamp.delivery_id.body` with SHA-256, using the configured endpoint
secret. Receivers must verify the signature before using any evidence. This is
an authenticated operator assertion, not independently verifiable LND proof.

## Compatibility and absence

- Existing `amount_msat` / `amount_sat` remain invoice **face amounts**.
- Existing `settled_at` remains the worker's **observation time**.
- Neither field is a substitute for actual settlement evidence.
- Forwarded invoices, `remote_verify` observations, unknown settlement sources,
  and test deliveries never carry local settlement proof. Even a custom test
  payload cannot inject `settlement_proof`.
- Historical records missing evidence omit it; there is no automatic backfill
  or fabrication on retry/replay. An explicit authoritative local refresh can
  persist newly observed evidence through the normal polling path.
- Absence means **unproven**, not unpaid. Consumers requiring authoritative
  evidence must defer credit rather than infer it from the legacy fields.

For fixed invoices, bind the authenticated outer payment hash, address and
application quote to the expected invoice, apply a period once idempotently,
and require actual paid msat to cover the fixed invoice amount. An overpayment
is not an error and must not create extra periods. No +/-10% tolerance rule is
part of this producer contract. This release change does not introduce a client
provisioning API or change normal LNURL policy/expiry defaults.
