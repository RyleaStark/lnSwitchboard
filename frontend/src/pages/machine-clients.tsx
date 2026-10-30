import { useRef, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { CopyButton } from "@/components/common"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Field, FieldLabel, FieldDescription } from "@/components/ui/field"
import { LoadingRows, PageError } from "@/components/common"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { api, type ClientScope } from "@/lib/api"

const scopeChoices: { value: ClientScope; label: string }[] = [
  { value: "addresses:create", label: "Create addresses" },
  { value: "addresses:read_own", label: "Read owned addresses" },
  { value: "invoices:create", label: "Create fixed invoices for owned addresses" },
]

export function MachineClients() {
  const [adding, setAdding] = useState(false)
  const [domain, setDomain] = useState("")
  const [url, setUrl] = useState("")
  const [secret, setSecret] = useState("")
  const [scopes, setScopes] = useState<ClientScope[]>([])
  const [token, setToken] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const locked = useRef(false)
  async function provision() {
    if (locked.current) return
    locked.current = true
    setBusy(true)
    setError("")
    const payload = { domain: domain.trim(), webhook_url: url.trim(), webhook_secret: secret, scopes }
    setSecret("")
    try {
      const result = await api.provisionClient(payload)
      setToken(result.token)
      setAdding(false)
      setDomain(""); setUrl(""); setScopes([])
      void clients.refetch()
    } catch {
      setError("Client provisioning failed or its outcome is unknown. Refresh the client list before retrying; revoke an unexpected client and provision again if its token was lost.")
    } finally { locked.current = false; setBusy(false) }
  }
  const [confirmId, setConfirmId] = useState<string | null>(null)
  async function revoke(id: string) {
    if (locked.current) return
    locked.current = true; setBusy(true); setError(""); setToken("")
    try { await api.revokeClient(id); setConfirmId(null); await clients.refetch() }
    catch { setError("Revocation could not be confirmed. Refresh the list to check access before retrying.") }
    finally { locked.current = false; setBusy(false) }
  }
  const clients = useQuery({ queryKey: ["machine-clients"], queryFn: api.machineClients })
  const status = useQuery({ queryKey: ["client-listener"], queryFn: api.clientListenerStatus, refetchInterval: 10000 })
  return <div className="flex min-w-0 flex-col gap-6">
    <Card>
      <CardHeader><CardTitle>Machine clients</CardTitle><CardDescription>Give a billing service scoped access without sharing operator credentials.</CardDescription></CardHeader>
      <CardContent className="flex flex-col gap-4">
        <p className="text-sm">Clients can only access addresses they own. Domain and webhook routing are fixed when you provision a client.</p>
        {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
        {token ? <section aria-label="One-time client token" className="flex min-w-0 flex-col gap-3 rounded-md border p-4">
          <h3 className="font-medium">Save this token now</h3><p className="text-sm">Shown once. Store it in your client’s secret manager, never in a URL, log or screenshot. Copying puts it on your system clipboard; clear that clipboard when finished.</p>
          <Field><FieldLabel htmlFor="client-token">Client token</FieldLabel><Input id="client-token" type="password" readOnly value={token} autoComplete="off" className="font-mono" onFocus={event => event.target.select()} /></Field>
          <div className="flex flex-wrap gap-2"><CopyButton value={token} label="Copy token" /><Button type="button" variant="outline" onClick={() => setToken("")}>Done — clear token</Button></div>
        </section> : null}
        {!adding ? <Button type="button" className="self-start" disabled={busy || Boolean(token)} onClick={() => { setAdding(true); setError("") }}>Add client</Button> : <form autoComplete="off" className="flex flex-col gap-4 rounded-md border p-4" onSubmit={event => { event.preventDefault(); void provision() }}>
          <Field><FieldLabel htmlFor="client-domain">Domain</FieldLabel><Input id="client-domain" required maxLength={253} value={domain} disabled={busy} onChange={event => setDomain(event.target.value)} /><FieldDescription>Use a lowercase domain already configured in Connections. This does not configure DNS or a tunnel.</FieldDescription></Field>
          <Field><FieldLabel htmlFor="client-webhook">Webhook URL</FieldLabel><Input id="client-webhook" type="url" required maxLength={2048} value={url} disabled={busy} onChange={event => setUrl(event.target.value)} /><FieldDescription>Fixed destination for this client’s allocated addresses. HTTP and private-network destinations require ALLOW_PRIVATE_WEBHOOKS=true; delivery still validates destinations. Configure it in Environment and restart if needed. Current private-webhook setting: {status.data ? status.data.allow_private_webhooks ? "enabled" : "disabled" : "unknown"}.</FieldDescription></Field>
          <Field><FieldLabel htmlFor="client-secret">Webhook signing secret</FieldLabel><Input id="client-secret" type="password" autoComplete="new-password" required minLength={32} maxLength={256} value={secret} disabled={busy} onChange={event => setSecret(event.target.value)} /><FieldDescription>32–256 characters. Use the same secret in your webhook receiver. Cleared on every submission; never returned by the list API.</FieldDescription></Field>
          <fieldset disabled={busy} className="flex flex-col gap-2"><legend className="mb-2 text-sm font-medium">Allowed scopes</legend>{scopeChoices.map(choice => <label key={choice.value} className="flex min-h-11 items-center gap-3 text-sm"><input type="checkbox" checked={scopes.includes(choice.value)} onChange={event => setScopes(current => event.target.checked ? [...current, choice.value] : current.filter(scope => scope !== choice.value))} />{choice.label}</label>)}</fieldset>
          <div className="flex flex-wrap justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => { setAdding(false); setSecret(""); setError("") }}>Cancel</Button><Button type="submit" disabled={busy || !scopes.length}>{busy ? "Provisioning…" : "Provision client"}</Button></div>
        </form>}
        <Button type="button" variant="outline" className="self-start" disabled={clients.isFetching || busy} onClick={() => void clients.refetch()}>Refresh clients</Button>
        {clients.isPending ? <LoadingRows /> : clients.isError ? <PageError message="Couldn’t load clients. Refresh to try again." onRetry={() => void clients.refetch()} /> : clients.data.clients.length === 0 ? <p className="text-sm text-muted-foreground">No machine clients yet.</p> : clients.data.clients.map(client => <div key={client.client_id} className="flex min-w-0 flex-col gap-2 rounded-md border p-4"><code className="break-all text-xs">{client.client_id}</code><span className="break-all">{client.domain}</span><Badge variant={client.revoked ? "secondary" : "default"}>{client.revoked ? "Revoked" : "Active"}</Badge><span className="break-all text-xs">{client.scopes.join(", ")}</span>{!client.revoked ? confirmId === client.client_id ? <div role="group" aria-label={`Revoke ${client.client_id}`} className="flex flex-col gap-3"><p className="text-sm">Revoke {client.client_id}? This blocks future requests but cannot cancel an accepted LND request, invalidate an issued invoice or undo a payment. Address and webhook records remain for outstanding payments.</p><div className="flex flex-wrap gap-2"><Button autoFocus type="button" variant="outline" disabled={busy} onClick={() => setConfirmId(null)}>Keep client</Button><Button type="button" variant="destructive" disabled={busy} onClick={() => void revoke(client.client_id)}>{busy ? "Revoking…" : "Confirm revoke"}</Button></div></div> : <Button type="button" variant="outline" className="self-start" disabled={busy || Boolean(confirmId) || Boolean(token)} onClick={() => setConfirmId(client.client_id)}>Revoke</Button> : null}</div>)}
      </CardContent>
    </Card>
    <Card><CardHeader><CardTitle>Private client endpoint</CardTitle></CardHeader><CardContent className="flex flex-col gap-3 text-sm">
      {status.isPending ? <p>Checking listener…</p> : status.isError ? <PageError message="Listener status unavailable. Do not assume the port is reachable." onRetry={() => void status.refetch()} /> : <><p>{!status.data.enabled ? "Listener disabled" : status.data.listening ? "Listener running" : "Listener not running"} — bind {status.data.host}:{status.data.port}</p><p>Use http://YOUR-NODE:{status.data.port}/api/client/v1 with Authorization: Bearer and your client token. A running listener does not prove host publication, firewall access or remote reachability.</p></>}
      <p>Umbrel publishes client-only port 22122. Keep the dashboard and provisioning behind Umbrel login on 22121; public LNURL uses 21212. Never forward the client port to the Internet. LAN HTTP is unencrypted; use a private VPN or TLS-protected transport.</p>
      <p>Outside Umbrel, configure CLIENT_API_ENABLED=true, CLIENT_API_HOST and CLIENT_API_PORT, then restart. Loopback binding only accepts local connections.</p>
      <p>Settlement proof is automatic for authoritative local LND settlements; there is no toggle. An authorized client chooses each fixed invoice amount and 14- or 30-day expiry per request, within configured limits. Ordinary LNURL expiry is unchanged.</p>
    </CardContent></Card>
  </div>
}
