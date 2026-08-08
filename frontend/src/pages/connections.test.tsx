import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"

import { ApiError, api, type CloudflareOAuthGrant, type ProviderConnection } from "@/lib/api"
import { ConnectionsPage } from "@/pages/connections"

import { vi } from "vitest"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: {
    connections: vi.fn(),
    cloudflareSetup: vi.fn(),
    beginCloudflareOAuth: vi.fn(),
    completeCloudflareOAuth: vi.fn(),
    cloudflareOAuthGrants: vi.fn(),
    deleteCloudflareOAuthGrant: vi.fn(),
    authorizeCloudflare: vi.fn(),
    cloudflareAuthorization: vi.fn(),
    cancelCloudflareAuthorization: vi.fn(),
    provisionCloudflare: vi.fn(),
    availableCloudflareDomains: vi.fn(),
    addCloudflareDomain: vi.fn(),
    removeCloudflareDomain: vi.fn(),
    refreshCloudflareStatus: vi.fn(),
    disconnectCloudflare: vi.fn(),
    tailscaleSetup: vi.fn(),
    beginTailscaleLogin: vi.fn(),
    tailscaleLoginStatus: vi.fn(),
    cancelTailscaleLogin: vi.fn(),
    refreshTailscaleStatus: vi.fn(),
    disconnectTailscale: vi.fn(),
  },
}))

const setup = {
  available: true,
  oauth_configured: true,
  configuration_error: null,
  origin: "http://lnswitchboard:21212",
  required_permissions: [
    "Account: Workers Scripts Edit",
    "Account: Zero Trust Edit",
    "Account: Access: Apps and Policies Edit",
    "Zone: Workers Routes Edit",
    "Zone: DNS Edit",
    "Zone: Zone Read",
  ],
  authorization_method: "oauth" as const,
}

const tailscaleSetup = {
  available: true,
  authorization_method: "web_login" as const,
  default_device_name: "lns",
  device_name_max_length: 63,
  public_origin: "http://127.0.0.1:21212",
  public_port: 443 as const,

  prerequisites: [
    "magic_dns",
    "https_certificates",
    "funnel_node_attribute",
    "funnel_port_443",
  ],
}

function tailscaleAuthUrl() {
  return "https://" + "login.tailscale.com" + "/a/" + "TEST_ONLY_AUTHORIZATION"
}

function oauthFlow() {
  return {
    flow_id: "flow-1",
    authorize_url: "https://dash.cloudflare.com/oauth2/authorize?client_id=lns&state=flow-state",
    expires_at: Math.floor(Date.now() / 1000) + 600,
  }
}

function oauthGrant(): CloudflareOAuthGrant {
  return {
    grant_id: "grant-1",
    scopes: "workers:write zerotrust:write dns:write",
    account_label: "Example account",
    account_metadata: { account_id: "a".repeat(32), account_name: "Example account" },
    access_token_expires_at: 4_000_000_000,
    has_refresh_token: true,
    created_at: 1_700_000_000,
    updated_at: 1_700_000_000,
  }
}

function cloudflareAuthorization() {
  return {
    accounts: [
      {
        id: "a".repeat(32),
        name: "Example account",
        zones: [{ id: "b".repeat(32), name: "example.com" }],
      },
    ],
  }
}

function renderPage(path = "/connections/cloudflare/") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const rendered = render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={client}>
        <ConnectionsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  )
  return { client, ...rendered }
}

function cloudflareConnection(domains: ProviderConnection["domains"] = [
  {
    hostname: "example.com",
    status: "active",
    zone_id: "b".repeat(32),
    external_id: "dns-id",
    last_error: null,
  },
]): ProviderConnection {
  return {
    id: "connection-id",
    provider: "cloudflare",
    external_id: "mesh-node-id",
    label: "Cloudflare",
    status: "connected",
    account_id: "a".repeat(32),
    public_metadata: { origin: "http://lnswitchboard:21212" },
    last_error: null,
    created_at: "2026-08-04T00:00:00Z",
    updated_at: "2026-08-04T00:00:00Z",
    domains,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "cloudflare", name: "Cloudflare", capability: "available", reason: null },
      { id: "tailscale", name: "Tailscale Funnel", capability: "available", reason: null },
    ],
    connections: [],
  })
  vi.mocked(api.cloudflareSetup).mockResolvedValue(setup)
  vi.mocked(api.cloudflareOAuthGrants).mockResolvedValue({ grants: [] })
  vi.mocked(api.availableCloudflareDomains).mockResolvedValue({ zones: [] })
  vi.mocked(api.tailscaleSetup).mockResolvedValue(tailscaleSetup)
  vi.mocked(api.tailscaleLoginStatus).mockRejectedValue(
    new ApiError(404, "Login not found", "Login not found"),
  )
  vi.mocked(api.cloudflareAuthorization).mockRejectedValue(
    new ApiError(404, "Authorization not found", "Authorization not found"),
  )
})

test("keeps Cloudflare visible but disabled when the connector is unavailable", async () => {
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      {
        id: "cloudflare",
        name: "Cloudflare",
        capability: "unavailable",
        reason: "connector_not_installed",
      },
    ],
    connections: [],
  })
  vi.mocked(api.cloudflareSetup).mockResolvedValue({ ...setup, available: false })

  renderPage()

  expect(await screen.findByRole("heading", { name: "Cloudflare" })).toBeVisible()
  expect(screen.getByText("Connector not installed")).toBeVisible()
  expect(screen.getByRole("button", { name: "Connect Cloudflare" })).toBeDisabled()
  expect(screen.getByLabelText("Completion method")).toBeDisabled()
  expect(screen.queryByLabelText(/API token/i)).not.toBeInTheDocument()
  expect(screen.getAllByText(/tokens never leave this device/)).not.toHaveLength(0)
  expect(document.body.textContent).not.toContain("22121")
})

test("explains when the deployment has not configured its OAuth client", async () => {
  vi.mocked(api.cloudflareSetup).mockResolvedValue({
    ...setup,
    available: false,
    oauth_configured: false,
    configuration_error: "Cloudflare OAuth is not configured for this deployment.",
  })

  renderPage()

  expect(await screen.findByText("OAuth not configured")).toBeVisible()
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Cloudflare OAuth is not configured for this deployment.",
  )
  expect(screen.getByRole("button", { name: "Connect Cloudflare" })).toBeDisabled()
})

test("shows the OAuth scopes the consent screen will request without token guidance", async () => {
  renderPage()

  for (const permission of setup.required_permissions) {
    expect(await screen.findByText(permission)).toBeVisible()
  }
  expect(screen.getByText(/Cloudflare will request these permissions/)).toBeVisible()
  expect(screen.queryByRole("link", { name: /api token/i })).not.toBeInTheDocument()
  expect(screen.queryByLabelText(/tunnel/i)).not.toBeInTheDocument()
})

test("begins OAuth in loopback mode by default and completes via paste-back", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginCloudflareOAuth).mockResolvedValue(oauthFlow())
  vi.mocked(api.completeCloudflareOAuth).mockResolvedValue(oauthGrant())
  vi.mocked(api.cloudflareOAuthGrants).mockResolvedValue({ grants: [oauthGrant()] })
  const { client } = renderPage()

  await user.click(await screen.findByRole("button", { name: "Connect Cloudflare" }))

  await waitFor(() => expect(api.beginCloudflareOAuth).toHaveBeenCalledWith("loopback"))
  expect(await screen.findByRole("link", { name: "Open Cloudflare authorization" })).toHaveAttribute(
    "href",
    oauthFlow().authorize_url,
  )
  expect(screen.getByText(/paste the code shown after authorizing/)).toBeVisible()
  expect(screen.getByLabelText("State")).toHaveValue("flow-state")

  await user.type(screen.getByLabelText("Authorization code"), "pasted-code")
  await user.click(screen.getByRole("button", { name: "Complete authorization" }))

  await waitFor(() =>
    expect(api.completeCloudflareOAuth).toHaveBeenCalledWith({
      code: "pasted-code",
      state: "flow-state",
    }),
  )
  expect(await screen.findByText("Example account")).toBeVisible()
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(document.body.textContent).not.toContain("pasted-code")
  expect(window.localStorage?.length ?? 0).toBe(0)
  expect(window.sessionStorage?.length ?? 0).toBe(0)
})

test("uses the page redirect mode when selected", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginCloudflareOAuth).mockResolvedValue(oauthFlow())
  renderPage()

  await user.selectOptions(await screen.findByLabelText("Completion method"), "page")
  await user.click(screen.getByRole("button", { name: "Connect Cloudflare" }))

  await waitFor(() => expect(api.beginCloudflareOAuth).toHaveBeenCalledWith("page"))
  expect(await screen.findByRole("link", { name: "Open Cloudflare authorization" })).toBeInTheDocument()
})

test("clears a rejected authorization code without retaining it", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginCloudflareOAuth).mockResolvedValue(oauthFlow())
  vi.mocked(api.completeCloudflareOAuth).mockRejectedValue(
    new Error("invalid_grant: authorization code expired"),
  )
  const { client } = renderPage()

  await user.click(await screen.findByRole("button", { name: "Connect Cloudflare" }))
  const codeInput = await screen.findByLabelText("Authorization code")
  await user.type(codeInput, "rejected-pasted-code")
  await user.click(screen.getByRole("button", { name: "Complete authorization" }))

  await waitFor(() => expect(codeInput).toHaveValue(""))
  expect(screen.getByRole("link", { name: "Open Cloudflare authorization" })).toBeInTheDocument()
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(document.body.textContent).not.toContain("rejected-pasted-code")
})

test("surfaces a begin failure verbatim and stays on the connect step", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginCloudflareOAuth).mockRejectedValue(
    new Error("Cloudflare OAuth client is not configured"),
  )
  renderPage()

  await user.click(await screen.findByRole("button", { name: "Connect Cloudflare" }))

  await waitFor(() => expect(api.beginCloudflareOAuth).toHaveBeenCalledTimes(1))
  expect(screen.getByRole("button", { name: "Connect Cloudflare" })).toBeEnabled()
  expect(screen.queryByRole("link", { name: "Open Cloudflare authorization" })).not.toBeInTheDocument()
})

test("selects grant, account, and zone, then provisions a hostname", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginCloudflareOAuth).mockResolvedValue(oauthFlow())
  vi.mocked(api.completeCloudflareOAuth).mockResolvedValue(oauthGrant())
  vi.mocked(api.cloudflareOAuthGrants).mockResolvedValue({ grants: [oauthGrant()] })
  vi.mocked(api.authorizeCloudflare).mockResolvedValue(cloudflareAuthorization())
  vi.mocked(api.provisionCloudflare).mockResolvedValue({
    ...cloudflareConnection([
      {
        hostname: "pay.example.com",
        status: "pending",
        zone_id: "b".repeat(32),
        external_id: "dns-id",
        last_error: null,
      },
    ]),
    status: "provisioning",
  })
  const { client } = renderPage()

  await user.click(await screen.findByRole("button", { name: "Connect Cloudflare" }))
  await user.type(await screen.findByLabelText("Authorization code"), "pasted-code")
  await user.click(screen.getByRole("button", { name: "Complete authorization" }))

  await user.click(await screen.findByRole("button", { name: "Use this authorization" }))
  await waitFor(() =>
    expect(api.authorizeCloudflare).toHaveBeenCalledWith({
      grant_id: "grant-1",
      account_id: "a".repeat(32),
    }),
  )

  await screen.findByRole("button", { name: "Create connection" })
  expect(screen.getByLabelText("Cloudflare account")).toHaveValue("a".repeat(32))
  expect(screen.getByLabelText("Domain")).toHaveValue("b".repeat(32))
  expect(screen.getByLabelText("Hostname")).toHaveValue("example.com")
  await user.clear(screen.getByLabelText("Hostname"))
  await user.type(screen.getByLabelText("Hostname"), "pay.example.com")
  await user.click(screen.getByRole("button", { name: "Create connection" }))

  await waitFor(() =>
    expect(vi.mocked(api.provisionCloudflare).mock.calls[0]?.[0]).toEqual({
      account_id: "a".repeat(32),
      zone_id: "b".repeat(32),
      hostname: "pay.example.com",
    }),
  )
  await waitFor(() =>
    expect(client.getQueryData(["cloudflare-authorization"])).toBeUndefined(),
  )
  expect(document.body.textContent).not.toContain("pasted-code")
})

test("resumes the grant picker after an automatic loopback redirect", async () => {
  vi.mocked(api.cloudflareOAuthGrants).mockResolvedValue({ grants: [oauthGrant()] })
  renderPage("/connections/cloudflare/?cloudflare=connected")

  expect(await screen.findByText("Example account")).toBeVisible()
  expect(screen.getByRole("button", { name: "Use this authorization" })).toBeEnabled()
  expect(api.beginCloudflareOAuth).not.toHaveBeenCalled()
})

test("shows an empty state when no grants exist and returns to the connect step", async () => {
  const user = userEvent.setup()
  renderPage("/connections/cloudflare/?cloudflare=connected")

  expect(await screen.findByText(/No Cloudflare authorizations yet/)).toBeVisible()
  await user.click(screen.getByRole("button", { name: "Connect Cloudflare again" }))
  expect(await screen.findByRole("button", { name: "Connect Cloudflare" })).toBeEnabled()
})

test("lists grants with expiry and deletes one after confirmation", async () => {
  const user = userEvent.setup()
  vi.mocked(api.cloudflareOAuthGrants).mockResolvedValue({ grants: [oauthGrant()] })
  vi.mocked(api.deleteCloudflareOAuthGrant).mockResolvedValue(null)
  renderPage("/connections/cloudflare/?cloudflare=connected")

  expect(await screen.findByText("Example account")).toBeVisible()
  expect(screen.getByText(/Access token expires/)).toBeVisible()
  await user.click(screen.getByRole("button", { name: "Delete authorization for Example account" }))
  await user.click(screen.getByRole("button", { name: "Delete authorization" }))

  await waitFor(() =>
    expect(vi.mocked(api.deleteCloudflareOAuthGrant).mock.calls[0]?.[0]).toBe("grant-1"),
  )
})

test("keeps connected management controls active when onboarding capability is unavailable", async () => {
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      {
        id: "cloudflare",
        name: "Cloudflare",
        capability: "unavailable",
        reason: "connector_not_installed",
      },
    ],
    connections: [cloudflareConnection([])],
  })
  vi.mocked(api.cloudflareSetup).mockResolvedValue({ ...setup, available: false })

  renderPage()

  const heading = await screen.findByRole("heading", { name: "Cloudflare" })
  expect(heading.closest('[data-slot="card"]')).toBeNull()
  expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled()
  expect(screen.getByRole("button", { name: "Disconnect" })).toBeEnabled()
})

test("guides back to the connect step when a domain operation requires reconnect", async () => {
  const user = userEvent.setup()
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "cloudflare", name: "Cloudflare", capability: "available", reason: null },
    ],
    connections: [cloudflareConnection()],
  })
  vi.mocked(api.refreshCloudflareStatus).mockRejectedValue(
    new ApiError(409, "Cloudflare authorization expired; reconnect Cloudflare", "Conflict"),
  )

  renderPage()

  await user.click(await screen.findByRole("button", { name: "Refresh status" }))

  const alert = await screen.findByRole("alert")
  expect(alert).toHaveTextContent("Cloudflare authorization expired; reconnect Cloudflare")
  expect(alert).toHaveTextContent(/restore domain management/)
  expect(screen.getByRole("button", { name: "Connect Cloudflare" })).toBeInTheDocument()
})

test("offers unused authorized zones and adds another Cloudflare domain", async () => {
  const user = userEvent.setup()
  const existing = cloudflareConnection()
  const added = cloudflareConnection([
    ...existing.domains,
    {
      hostname: "example.net",
      status: "pending",
      zone_id: "d".repeat(32),
      external_id: "dns-id-2",
      last_error: null,
    },
  ])
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "cloudflare", name: "Cloudflare", capability: "available", reason: null },
    ],
    connections: [existing],
  })
  vi.mocked(api.availableCloudflareDomains).mockResolvedValue({
    zones: [{ id: "d".repeat(32), name: "example.net" }],
  })
  vi.mocked(api.addCloudflareDomain).mockResolvedValue(added)

  renderPage()

  expect(await screen.findByText("Your Lightning Addresses are available at this hostname.")).toBeVisible()
  await user.click(await screen.findByRole("button", { name: "Add Domain" }))
  expect(screen.getByLabelText("Additional domain")).toHaveValue("d".repeat(32))
  expect(screen.getByLabelText("Hostname")).toHaveValue("example.net")
  await user.clear(screen.getByLabelText("Hostname"))
  await user.type(screen.getByLabelText("Hostname"), "pay.example.net")
  await user.click(screen.getByRole("button", { name: "Add selected domain" }))

  await waitFor(() =>
    expect(api.addCloudflareDomain).toHaveBeenCalledWith({
      connectionId: "connection-id",
      zoneId: "d".repeat(32),
      hostname: "pay.example.net",
    }),
  )
})


test("only claims Lightning Address availability for active Cloudflare domains", async () => {
  const connection = cloudflareConnection([
    {
      hostname: "example.com",
      status: "active",
      zone_id: "b".repeat(32),
      external_id: "dns-id",
      last_error: null,
    },
    {
      hostname: "pending.example.com",
      status: "pending",
      zone_id: "b".repeat(32),
      external_id: "dns-id-2",
      last_error: null,
    },
    {
      hostname: "broken.example.com",
      status: "error",
      zone_id: "b".repeat(32),
      external_id: "dns-id-3",
      last_error: "Managed route is missing",
    },
  ])
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "cloudflare", name: "Cloudflare", capability: "available", reason: null },
    ],
    connections: [connection],
  })

  renderPage()

  await screen.findByText("broken.example.com")
  expect(
    screen.getAllByText("Your Lightning Addresses are available at this hostname."),
  ).toHaveLength(1)
  expect(screen.getByText("Managed route is missing")).toBeVisible()
})


test("removes one domain without disconnecting Cloudflare", async () => {
  const user = userEvent.setup()
  const connected = cloudflareConnection([
    ...cloudflareConnection().domains,
    {
      hostname: "example.net",
      status: "active",
      zone_id: "d".repeat(32),
      external_id: "dns-id-2",
      last_error: null,
    },
  ])
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "cloudflare", name: "Cloudflare", capability: "available", reason: null },
    ],
    connections: [connected],
  })
  vi.mocked(api.removeCloudflareDomain).mockResolvedValue(cloudflareConnection())

  renderPage()

  await screen.findByText("example.net")
  await user.click(screen.getByRole("button", { name: "Remove example.net" }))
  await user.click(screen.getByRole("button", { name: "Remove domain" }))

  await waitFor(() =>
    expect(api.removeCloudflareDomain).toHaveBeenCalledWith({
      connectionId: "connection-id",
      hostname: "example.net",
    }),
  )
  expect(api.disconnectCloudflare).not.toHaveBeenCalled()
})

test("asks for a device name and suggests lns by default", async () => {
  renderPage("/connections/tailscale/")

  const deviceName = await screen.findByLabelText("Device name")
  expect(deviceName).toHaveValue("lns")
  expect(screen.getByRole("button", { name: "Connect Tailscale" })).toBeEnabled()
  expect(screen.queryByLabelText("Public hostname")).not.toBeInTheDocument()
  expect(screen.queryByLabelText(/API token/i)).not.toBeInTheDocument()
  expect(document.body.textContent).not.toContain("22121")
})

test("opens the transient Tailscale login link and QR without query or browser storage", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "needs_login",
    device_name: "my-node",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })
  const { client } = renderPage("/connections/tailscale/")

  const deviceName = await screen.findByLabelText("Device name")
  await user.clear(deviceName)
  await user.type(deviceName, "My-Node")
  await user.click(screen.getByRole("button", { name: "Connect Tailscale" }))

  await waitFor(() => expect(api.beginTailscaleLogin).toHaveBeenCalledWith("my-node"))
  expect(await screen.findByRole("link", { name: "Open Tailscale login" })).toHaveAttribute(
    "href",
    tailscaleAuthUrl(),
  )
  expect(await screen.findByRole("img", { name: "Tailscale login QR code" })).toHaveAttribute(
    "src",
    expect.stringMatching(/^data:image\/svg\+xml/),
  )
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(window.localStorage?.length ?? 0).toBe(0)
  expect(window.sessionStorage?.length ?? 0).toBe(0)

  await user.click(screen.getByRole("button", { name: "Check status" }))
  await waitFor(() =>
    expect(screen.queryByRole("link", { name: "Open Tailscale login" })).not.toBeInTheDocument(),
  )
  expect(screen.queryByRole("img", { name: "Tailscale login QR code" })).not.toBeInTheDocument()
})

test("blocks connect while startup recovery is in flight", async () => {
  let rejectRecovery: ((reason: unknown) => void) | undefined
  vi.mocked(api.tailscaleLoginStatus).mockReturnValueOnce(
    new Promise((_, reject) => {
      rejectRecovery = reject
    }),
  )

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))

  const connectButton = await screen.findByRole("button", { name: "Connect Tailscale" })
  expect(connectButton).toBeDisabled()
  act(() => connectButton.click())
  expect(api.beginTailscaleLogin).not.toHaveBeenCalled()

  await act(async () => {
    rejectRecovery?.(new ApiError(404, "not found", "Not found"))
  })
  await waitFor(() => expect(connectButton).toBeEnabled())
})

test("permits only one same-tick connect operation", async () => {
  let resolveBegin:
    | ((value: Awaited<ReturnType<typeof api.beginTailscaleLogin>>) => void)
    | undefined
  vi.mocked(api.beginTailscaleLogin).mockReturnValueOnce(
    new Promise((resolve) => {
      resolveBegin = resolve
    }),
  )

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))
  const connectButton = await screen.findByRole("button", { name: "Connect Tailscale" })

  act(() => {
    connectButton.click()
    connectButton.click()
  })
  expect(api.beginTailscaleLogin).toHaveBeenCalledTimes(1)

  await act(async () => {
    resolveBegin?.({
      state: "needs_login",
      device_name: "lns",
      auth_url: tailscaleAuthUrl(),
      expires_in_seconds: 300,
    })
  })
  expect(await screen.findByRole("link", { name: "Open Tailscale login" })).toBeInTheDocument()
})

test("serializes Tailscale status checks and cancellation", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "needs_login",
    device_name: "lns",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })
  renderPage("/connections/tailscale/")

  const connectButton = await screen.findByRole("button", { name: "Connect Tailscale" })
  await waitFor(() => expect(connectButton).toBeEnabled())
  await user.click(connectButton)
  await screen.findByRole("link", { name: "Open Tailscale login" })

  let resolveStatus: ((value: {
    state: "needs_login"
    device_name: string
    auth_url: string
    expires_in_seconds: number
  }) => void) | undefined
  vi.mocked(api.tailscaleLoginStatus).mockImplementationOnce(
    () => new Promise((resolve) => { resolveStatus = resolve }),
  )

  await user.click(screen.getByRole("button", { name: "Check status" }))
  expect(await screen.findByRole("button", { name: "Checking…" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled()

  resolveStatus?.({
    state: "needs_login",
    device_name: "lns",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })
  await waitFor(() => expect(screen.getByRole("button", { name: "Check status" })).toBeEnabled())

  let resolveCancel: ((value: { cancelled: boolean }) => void) | undefined
  vi.mocked(api.cancelTailscaleLogin).mockImplementationOnce(
    () => new Promise((resolve) => { resolveCancel = resolve }),
  )
  await user.click(screen.getByRole("button", { name: "Cancel" }))
  expect(await screen.findByRole("button", { name: "Cancelling…" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "Check status" })).toBeDisabled()

  resolveCancel?.({ cancelled: true })
  await waitFor(() =>
    expect(screen.queryByRole("link", { name: "Open Tailscale login" })).not.toBeInTheDocument(),
  )
})

test("keeps the authorization link when a status check is rejected", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "needs_login",
    device_name: "lns",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))
  await user.click(await screen.findByRole("button", { name: "Connect Tailscale" }))
  await screen.findByRole("link", { name: "Open Tailscale login" })
  await waitFor(() => expect(api.beginTailscaleLogin).toHaveBeenCalledTimes(1))
  await screen.findByRole("button", { name: "Check status" })

  vi.mocked(api.tailscaleLoginStatus).mockRejectedValueOnce(
    new ApiError(403, "administration forbidden", "Forbidden"),
  )
  await user.click(screen.getByRole("button", { name: "Check status" }))

  expect(screen.getByRole("link", { name: "Open Tailscale login" })).toBeInTheDocument()
  expect(screen.getByAltText("Tailscale login QR code")).toBeInTheDocument()
})

test("keeps the authorization link when cancellation is rejected", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "needs_login",
    device_name: "lns",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })
  vi.mocked(api.cancelTailscaleLogin).mockRejectedValueOnce(
    new ApiError(403, "administration forbidden", "Forbidden"),
  )

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))
  await user.click(await screen.findByRole("button", { name: "Connect Tailscale" }))
  await screen.findByRole("link", { name: "Open Tailscale login" })
  await waitFor(() => expect(api.beginTailscaleLogin).toHaveBeenCalledTimes(1))
  await screen.findByRole("button", { name: "Check status" })
  await user.click(screen.getByRole("button", { name: "Cancel" }))

  expect(screen.getByRole("link", { name: "Open Tailscale login" })).toBeInTheDocument()
  expect(screen.getByAltText("Tailscale login QR code")).toBeInTheDocument()
})

test("does not poll while cancellation is pending", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "needs_login",
    device_name: "lns",
    auth_url: tailscaleAuthUrl(),
    expires_in_seconds: 300,
  })
  let resolveCancel: ((value: { cancelled: boolean }) => void) | undefined
  vi.mocked(api.cancelTailscaleLogin).mockReturnValueOnce(
    new Promise<{ cancelled: boolean }>((resolve) => {
      resolveCancel = resolve
    }),
  )

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))
  await user.click(await screen.findByRole("button", { name: "Connect Tailscale" }))
  await screen.findByRole("link", { name: "Open Tailscale login" })
  await waitFor(() => expect(api.beginTailscaleLogin).toHaveBeenCalledTimes(1))
  await screen.findByRole("button", { name: "Check status" })
  const statusCalls = vi.mocked(api.tailscaleLoginStatus).mock.calls.length

  fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
  await new Promise((resolve) => window.setTimeout(resolve, 2_200))
  expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(statusCalls)

  resolveCancel?.({ cancelled: true })
  await waitFor(() => expect(api.cancelTailscaleLogin).toHaveBeenCalledTimes(1))
})

test("explains that Tailscale onboarding needs its connector", async () => {
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "tailscale", name: "Tailscale Funnel", capability: "unavailable", reason: "connector_not_installed" },
    ],
    connections: [],
  })

  renderPage("/connections/tailscale/")

  expect(await screen.findByText("Connector not installed")).toBeInTheDocument()
  expect(screen.getByText(/Add the Tailscale sidecar to this deployment stack/)).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Connect Tailscale" })).toBeDisabled()
  expect(api.tailscaleSetup).not.toHaveBeenCalled()
  expect(api.tailscaleLoginStatus).not.toHaveBeenCalled()
})

test("shows missing tailnet prerequisites without changing policy", async () => {
  const user = userEvent.setup()
  vi.mocked(api.beginTailscaleLogin).mockResolvedValue({
    state: "prerequisites_required",
    device_name: "lns",
    hostname: "lns.example.ts.net",
    missing_prerequisites: ["magic_dns", "funnel_port_443"],
  })

  renderPage("/connections/tailscale/")
  await waitFor(() => expect(api.tailscaleLoginStatus).toHaveBeenCalledTimes(1))
  await user.click(await screen.findByRole("button", { name: "Connect Tailscale" }))

  expect(await screen.findByText("Tailnet setup required")).toBeInTheDocument()
  expect(screen.getByText(/Enable MagicDNS/)).toBeInTheDocument()
  expect(screen.getByText(/Allow Funnel on HTTPS port 443/)).toBeInTheDocument()
  expect(screen.getByText(/will not change tailnet policy automatically/)).toBeInTheDocument()
})

test("disables existing Tailscale management when its connector is unavailable", async () => {
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      {
        id: "tailscale",
        name: "Tailscale Funnel",
        capability: "unavailable",
        reason: "connector_not_installed",
      },
    ],
    connections: [
      {
        id: "ts-connection",
        provider: "tailscale",
        label: "Tailscale Funnel",
        status: "connected",
        last_error: null,
        external_id: "node-123",
        account_id: null,
        public_metadata: { device_name: "lns", origin: "http://127.0.0.1:21212" },
        domains: [
          {
            hostname: "lns.example.ts.net",
            status: "active",
            external_id: null,
            zone_id: null,
            last_error: null,
          },
        ],
        created_at: "2026-08-04T00:00:00Z",
        updated_at: "2026-08-04T00:00:00Z",
      },
    ],
  })

  renderPage("/connections/tailscale/")

  expect(await screen.findByText("lns.example.ts.net")).toBeInTheDocument()
  expect(screen.getByText(/Restore the Tailscale connector to refresh or disconnect/)).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Refresh status" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "Disconnect" })).toBeDisabled()
  expect(api.tailscaleSetup).not.toHaveBeenCalled()
  expect(api.tailscaleLoginStatus).not.toHaveBeenCalled()
})

test("renders connected Tailscale refresh and disconnect controls", async () => {
  vi.mocked(api.connections).mockResolvedValue({
    providers: [
      { id: "tailscale", name: "Tailscale Funnel", capability: "available", reason: null },
    ],
    connections: [
      {
        id: "ts-connection",
        provider: "tailscale",
        label: "Tailscale Funnel",
        status: "connected",
        last_error: null,
        external_id: "node-123",
        account_id: null,
        public_metadata: { device_name: "lns", origin: "http://127.0.0.1:21212" },
        domains: [
          {
            hostname: "lns.example.ts.net",
            status: "active",
            external_id: null,
            zone_id: null,
            last_error: null,
          },
        ],
        created_at: "2026-08-04T00:00:00Z",
        updated_at: "2026-08-04T00:00:00Z",
      },
    ],
  })

  renderPage("/connections/tailscale/")

  expect(await screen.findByText("lns.example.ts.net")).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Refresh status" })).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Copy hostname" })).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Disconnect" })).toBeInTheDocument()
})
