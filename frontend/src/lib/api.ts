export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue }

export type PageResponse<T> = {
  items: T[]
  page: number
  page_size: number
  total_items: number
  total_pages: number
  has_next: boolean
  has_prev: boolean
  query?: string
}

export type SummaryStats = {
  connected_domains: number
  requests_24h: number
  requests_7d: number
  invoices_total: number
  invoices_paid: number
  invoices_paid_24h: number
  total_sats_routed: number
  sats_routed_7d: number
  invoice_activity: Array<{
    date: string
    sats: number
    paid: number
    created: number
    pending: number
    settled: number
    expired: number
  }>
}

export type RequestLog = {
  timestamp: string
  username: string
  ip: string
  event: string
  domain?: string | null
  amount_msat?: number | null
  status?: string
  message?: string | null
  details?: JsonValue
}

export type InvoiceEvent = {
  id: number
  created_at: string
  username: string
  domain?: string | null
  ip?: string | null
  amount_msat?: number | null
  amount_sat?: number | null
  payment_hash?: string | null
  payment_request?: string | null
  settled: boolean
  expired: boolean
  status: string
  next_check_at?: string | null
  last_checked_at?: string | null
  expires_at?: string | null
  settled_at?: string | null
  request_log_id?: number | null
  details?: JsonValue
}

export type Channel = {
  active?: boolean
  alias?: string | null
  peer_alias?: string | null
  remote_pubkey?: string | null
  chan_id?: string | number | null
  channel_id?: string | number | null
  channel_point?: string | null
  capacity_sat?: number | null
  local_balance_sat?: number | null
  remote_balance_sat?: number | null
  local_chan_reserve_sat?: number | null
  remote_chan_reserve_sat?: number | null
  receiving_capacity_sat?: number | null
  sendable_balance_sat?: number | null
  sendable_capacity_sat?: number | null
}

export type WebhookEndpointFilters = {
  tags?: string[]
  min_msat?: number | null
  max_msat?: number | null
  route?: "any" | "local" | "forwarded"
  require_comment?: boolean
  payer_data_field?: string | null
}

export type WebhookEndpoint = {
  id?: string | null
  url: string
  label?: string | null
  secret?: string | null
  secret_configured?: boolean
  filters?: WebhookEndpointFilters
}

export type LNAddress = {
  id: string
  local_part: string
  domain: string
  identifier: string
  routing_mode?: "local" | "forward"
  forward_to?: string | null
  base_local_part?: string | null
  tag?: string | null
  min_sats?: number | null
  max_sats?: number | null
  metadata_description?: string | null
  success_message?: string | null
  webhook_urls?: string[]
  webhook_endpoints?: WebhookEndpoint[]
  webhook_url?: string | null
  payer_data?: Record<string, boolean>
  created_at?: string | null
  updated_at?: string | null
}

export type LNAddressPayload = {
  local_part: string
  domain: string
  routing_mode?: "local" | "forward"
  forward_to?: string | null
  min_sats: number | null
  max_sats: number | null
  metadata_description: string | null
  success_message: string | null
  webhook_urls: string[]
  webhook_endpoints?: WebhookEndpoint[]
  payer_data?: Record<string, boolean> | null
}

export type ForwardingValidation = {
  valid: boolean
  forward_to: string
  callback: string
  min_sendable_msat: number
  max_sendable_msat: number
  metadata: string
}

export type Identity = {
  id: string
  local_part: string
  domain: string
  identifier: string
  npub: string
  pubkey_hex: string
  relays: string[]
  created_at?: string | null
  updated_at?: string | null
}

export type IdentityPayload = {
  local_part: string
  domain: string
  npub: string
  relays: string[]
}

export type EnvSetting = {
  key: string
  label: string
  description: string
  type: "text" | "number" | "textarea"
  category: string
  editable: boolean
  value: string
  hint_link?: { label?: string; href: string }
}

export type DeploymentEnv = "DOCKER" | "UMBREL" | "UMBREL_DEV"

export type VersionInfo = {
  version: string
  dep_env: DeploymentEnv
}

export type AuthStatus = {
  configured: boolean
  source: "manual" | "file"
  manual_entry_allowed: boolean
  path?: string | null
  error?: string | null
}

export type LndStatus = {
  connected: boolean
  status: "connected" | "not_configured" | "error"
  message: string
  info_permission?: boolean | null
  invoice_permissions?: boolean | null
  tls_status: "valid" | "expired" | "not_yet_valid" | "missing" | "invalid" | "unknown"
  tls_message: string
  tls_expires_at?: string | null
}

export type NostrZapSignerStatus = {
  configured: boolean
  pubkey?: string | null
  path?: string | null
  error?: string | null
}

export type WebhookAttempt = {
  id: number
  delivery_id: number
  attempted_at: string
  attempt_number: number
  success: boolean
  status_code?: number | null
  latency_ms?: number | null
  error?: string | null
  response_body?: string | null
}

export type WebhookDelivery = {
  id: number
  created_at: string
  updated_at: string
  kind: string
  event: string
  target: string
  status: string
  payload?: JsonValue
  headers?: JsonValue
  address_id?: string | null
  invoice_event_id?: number | null
  request_log_id?: number | null
  attempts?: WebhookAttempt[]
  last_attempt?: WebhookAttempt | null
}

export type ConnectionProvider = {
  id: string
  name: string
  capability: "available" | "unavailable"
  reason: string | null
}

export type ConnectedDomain = {
  hostname: string
  status: "pending" | "active" | "error"
  external_id: string | null
  zone_id: string | null
  last_error: string | null
}

export type ProviderConnection = {
  id: string
  provider: string
  external_id: string
  label: string
  status: "disconnected" | "authorizing" | "provisioning" | "connected" | "degraded" | "error"
  account_id: string | null
  public_metadata: Record<string, JsonValue>
  last_error: string | null
  created_at: string
  updated_at: string
  domains: ConnectedDomain[]
}

export type ConnectionsResponse = {
  providers: ConnectionProvider[]
  connections: ProviderConnection[]
}

export type CloudflareSetup = {
  available: boolean
  oauth_configured: boolean
  configuration_error: string | null
  origin: string
  required_permissions: string[]
  authorization_method: "oauth"
}

export type CloudflareAuthorization = {
  accounts: Array<{ id: string; name: string; zones: Array<{ id: string; name: string }> }>
}

export type CloudflareProvisionPayload = {
  account_id: string
  zone_id: string
  hostname: string
}

export type CloudflareOAuthRedirectMode = "loopback" | "page"

export type CloudflareOAuthFlow = {
  flow_id: string
  authorize_url: string
  expires_at: number
}

export type CloudflareOAuthGrant = {
  grant_id: string
  scopes: string
  account_label: string | null
  account_metadata: Record<string, JsonValue>
  access_token_expires_at: number | null
  has_refresh_token: boolean
  created_at: number | null
  updated_at: number | null
}

export type CloudflareZone = {
  id: string
  name: string
}

export type TailscaleSetup = {
  available: boolean
  authorization_method: "web_login"
  default_device_name: string
  device_name_max_length: number
  public_origin: string
  public_port: 443
  prerequisites: string[]
}

export type TailscaleLogin = {
  state: "needs_login" | "approval_required" | "prerequisites_required" | "connected" | "expired"
  device_name: string
  auth_url?: string | null
  expires_in_seconds?: number
  approval_kind?: "device" | "tailnet_lock" | "user"
  hostname?: string
  missing_prerequisites?: string[]
  connection?: ProviderConnection
}

export type ZrokSetup = {
  available: boolean
  modes: Array<"cloud" | "self_hosted">
  cloud_api_endpoint: string
  default_namespace: string
  public_origin: string
  cloud_interstitial_warning: boolean
}

export type ZrokProvisionPayload = {
  mode: "cloud" | "self_hosted"
  account_token: string
  api_endpoint?: string
  namespace: string
  name: string
}

export class ApiError extends Error {
  status: number
  detail: unknown

  constructor(status: number, detail: unknown, fallback: string) {
    super(normalizeApiErrorDetail(detail) || fallback)
    this.name = "ApiError"
    this.status = status
    this.detail = detail
  }
}

export function normalizeApiErrorDetail(detail: unknown): string {
  if (typeof detail === "string") return detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item
        if (item && typeof item === "object" && "msg" in item) {
          return String((item as { msg: unknown }).msg)
        }
        return ""
      })
      .filter(Boolean)
      .join(" ")
  }
  if (detail && typeof detail === "object") {
    if ("detail" in detail) return normalizeApiErrorDetail((detail as { detail: unknown }).detail)
    if ("message" in detail) return normalizeApiErrorDetail((detail as { message: unknown }).message)
  }
  return ""
}

function buildApiUrl(path: string): string {
  const normalized = path.startsWith("/") ? path.slice(1) : path
  return `${window.location.origin}/${normalized}`
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(buildApiUrl(path), {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  })
  const payload = await response.json().catch(() => null)
  if (!response.ok) {
    throw new ApiError(response.status, payload, `Request failed with HTTP ${response.status}`)
  }
  return payload as T
}

export const api = {
  health: () => request<{ status: string }>("api/health"),
  version: () => request<VersionInfo>("api/version"),
  lndStatus: () => request<LndStatus>("api/lnd/status"),
  authStatus: () => request<AuthStatus>("api/auth/status"),
  saveMacaroon: (macaroon: string) =>
    request<{ status: string }>("api/auth/macaroon", {
      method: "POST",
      body: JSON.stringify({ macaroon }),
    }),
  zapSignerStatus: () => request<NostrZapSignerStatus>("api/nostr/zap-signer"),
  generateZapSigner: () =>
    request<NostrZapSignerStatus>("api/nostr/zap-signer/generate", {
      method: "POST",
    }),
  importZapSigner: (privateKey: string) =>
    request<NostrZapSignerStatus>("api/nostr/zap-signer/import", {
      method: "POST",
      body: JSON.stringify({ private_key: privateKey }),
    }),
  summary: (tzOffsetMinutes: number) =>
    request<SummaryStats>(`api/stats/summary?tz_offset_minutes=${tzOffsetMinutes}`),
  logs: (page: number, pageSize: number, query: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (query.trim()) params.set("q", query.trim())
    return request<PageResponse<RequestLog>>(`api/logs/recent?${params}`)
  },
  clearLogs: () => request<{ status: string }>("api/logs/recent", { method: "DELETE" }),
  invoices: (page: number, pageSize: number, query: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (query.trim()) params.set("q", query.trim())
    return request<PageResponse<InvoiceEvent>>(`api/invoices?${params}`)
  },
  channels: () =>
    request<{ channels: Channel[]; total_receiving_capacity_sat: number }>("api/channels/public"),
  addresses: () => request<{ items: LNAddress[] }>("api/lnaddresses"),
  validateForwardingAddress: (payload: { forward_to: string }) =>
    request<ForwardingValidation>("api/lnaddresses/forwarding/validate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createAddress: (payload: LNAddressPayload) =>
    request<{ item: LNAddress }>("api/lnaddresses", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateAddress: (id: string, payload: LNAddressPayload) =>
    request<{ item: LNAddress }>(`api/lnaddresses/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteAddress: (id: string) => request<{ status: string }>(`api/lnaddresses/${id}`, { method: "DELETE" }),
  identities: () => request<{ items: Identity[] }>("api/nip05/identities"),
  createIdentity: (payload: IdentityPayload) =>
    request<{ item: Identity }>("api/nip05/identities", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateIdentity: (id: string, payload: IdentityPayload) =>
    request<{ item: Identity }>(`api/nip05/identities/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deleteIdentity: (id: string) => request<{ status: string }>(`api/nip05/identities/${id}`, { method: "DELETE" }),
  webhookDeliveries: (page: number, pageSize: number, query: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (query.trim()) params.set("q", query.trim())
    return request<PageResponse<WebhookDelivery>>(`api/webhooks/deliveries?${params}`)
  },
  replayWebhookDelivery: (id: number) =>
    request<{ status: string }>(`api/webhooks/deliveries/${id}/replay`, { method: "POST" }),
  testWebhook: (payload: { url: string; secret?: string | null }) =>
    request<{ status: string }>("api/webhooks/test", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  envSettings: () => request<{ settings: EnvSetting[] }>("api/settings/env"),
  updateEnvSettings: (values: Record<string, string>) =>
    request<{ updated: string[]; restart_required: boolean }>("api/settings/env", {
      method: "PUT",
      body: JSON.stringify({ values }),
    }),
  connections: () => request<ConnectionsResponse>("api/connections"),
  cloudflareSetup: () => request<CloudflareSetup>("api/connections/cloudflare/setup"),
  beginCloudflareOAuth: (redirectMode: CloudflareOAuthRedirectMode = "loopback") =>
    request<CloudflareOAuthFlow>("api/cloudflare/oauth/begin", {
      method: "POST",
      body: JSON.stringify({ redirect_mode: redirectMode }),
      cache: "no-store",
    }),
  completeCloudflareOAuth: (payload: { code: string; state: string }) =>
    request<CloudflareOAuthGrant>("api/cloudflare/oauth/complete", {
      method: "POST",
      body: JSON.stringify(payload),
      cache: "no-store",
    }),
  cloudflareOAuthGrants: () =>
    request<{ grants: CloudflareOAuthGrant[] }>("api/cloudflare/oauth/grants", {
      cache: "no-store",
    }),
  deleteCloudflareOAuthGrant: (grantId: string) =>
    request<null>(`api/cloudflare/oauth/grants/${encodeURIComponent(grantId)}`, {
      method: "DELETE",
    }),
  authorizeCloudflare: (payload: { grant_id: string; account_id?: string }) =>
    request<CloudflareAuthorization>("api/connections/cloudflare/authorize", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  cloudflareAuthorization: () =>
    request<CloudflareAuthorization>("api/connections/cloudflare/authorization"),
  cancelCloudflareAuthorization: () =>
    request<{ cancelled: boolean }>("api/connections/cloudflare/authorization", {
      method: "DELETE",
    }),
  provisionCloudflare: (payload: CloudflareProvisionPayload) =>
    request<ProviderConnection>("api/connections/cloudflare/provision", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  availableCloudflareDomains: (connectionId: string) =>
    request<{ zones: CloudflareZone[] }>(
      `api/connections/cloudflare/${connectionId}/domains/available`,
      { cache: "no-store" },
    ),
  addCloudflareDomain: ({ connectionId, zoneId, hostname }: { connectionId: string; zoneId: string; hostname: string }) =>
    request<ProviderConnection>(`api/connections/cloudflare/${connectionId}/domains`, {
      method: "POST",
      body: JSON.stringify({ zone_id: zoneId, hostname }),
    }),
  removeCloudflareDomain: ({ connectionId, hostname }: { connectionId: string; hostname: string }) =>
    request<ProviderConnection>(`api/connections/cloudflare/${connectionId}/domains/${encodeURIComponent(hostname)}`, {
      method: "DELETE",
    }),
  refreshCloudflareStatus: (connectionId: string) =>
    request<ProviderConnection>(`api/connections/cloudflare/${connectionId}/status`, {
      method: "POST",
    }),
  reauthorizeCloudflare: (connectionId: string) =>
    request<ProviderConnection>(
      `api/connections/cloudflare/${encodeURIComponent(connectionId)}/reauthorize`,
      { method: "POST" },
    ),
  disconnectCloudflare: (connectionId: string) =>
    request<{ disconnected: boolean }>(`api/connections/cloudflare/${connectionId}`, {
      method: "DELETE",
    }),
  tailscaleSetup: () => request<TailscaleSetup>("api/connections/tailscale/setup"),
  beginTailscaleLogin: (deviceName: string) =>
    request<TailscaleLogin>("api/connections/tailscale/login", {
      method: "POST",
      body: JSON.stringify({ device_name: deviceName }),
      cache: "no-store",
    }),
  tailscaleLoginStatus: () =>
    request<TailscaleLogin>("api/connections/tailscale/login", { cache: "no-store" }),
  cancelTailscaleLogin: () =>
    request<{ cancelled: boolean }>("api/connections/tailscale/login", {
      method: "DELETE",
      cache: "no-store",
    }),
  refreshTailscaleStatus: (connectionId: string) =>
    request<ProviderConnection>(`api/connections/tailscale/${connectionId}/status`, {
      method: "POST",
    }),
  disconnectTailscale: (connectionId: string) =>
    request<{ disconnected: boolean }>(`api/connections/tailscale/${connectionId}`, {
      method: "DELETE",
    }),
  zrokSetup: () => request<ZrokSetup>("api/connections/zrok/setup"),
  provisionZrok: (payload: ZrokProvisionPayload) =>
    request<ProviderConnection>("api/connections/zrok/provision", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  refreshZrokStatus: (connectionId: string) =>
    request<ProviderConnection>(`api/connections/zrok/${connectionId}/status`, {
      method: "POST",
    }),
  disconnectZrok: (connectionId: string) =>
    request<{ disconnected: boolean }>(`api/connections/zrok/${connectionId}`, {
      method: "DELETE",
    }),
}
