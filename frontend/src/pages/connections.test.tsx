import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router"

import { ApiError, api } from "@/lib/api"
import { ConnectionsPage } from "@/pages/connections"

import { vi } from "vitest"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: {
    connections: vi.fn(),
    cloudflareSetup: vi.fn(),
    authorizeCloudflare: vi.fn(),
    cloudflareAuthorization: vi.fn(),
    cancelCloudflareAuthorization: vi.fn(),
    provisionCloudflare: vi.fn(),
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
  origin: "http://lnswitchboard:21212",
  required_permissions: [
    "Cloudflare One Connector: cloudflared Write",
    "DNS Write",
    "Zone Read",
    "Account Settings Read",
  ],
  authorization_method: "api_token" as const,
}

const tailscaleSetup = {
  available: true,
  authorization_method: "web_login" as const,
  default_device_name: "lns",
  device_name_max_length: 63,
  public_origin: "http://127.0.0.1:21212",
  public_port: 443 as const,
  required_tag: "tag:lnswitchboard",
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

  expect(await screen.findByRole("heading", { name: "Cloudflare Tunnel" })).toBeVisible()
  expect(screen.getByText("Connector not installed")).toBeVisible()
  expect(screen.getByRole("button", { name: "Validate token" })).toBeDisabled()
  expect(screen.getByLabelText(/API token/i)).toBeDisabled()
  expect(document.body.textContent).not.toContain("22121")
})

test("guides token creation and clears the token after secure authorization", async () => {
  const user = userEvent.setup()
  vi.mocked(api.authorizeCloudflare).mockResolvedValue({ accounts: [] })
  const { client } = renderPage()

  const tokenInput = await screen.findByLabelText(/API token/i)
  expect(tokenInput).toHaveAttribute("type", "password")
  expect(tokenInput).toHaveAttribute("autocomplete", "off")
  expect(screen.getByRole("link", { name: /create a scoped token/i })).toHaveAttribute(
    "href",
    "https://dash.cloudflare.com/profile/api-tokens",
  )
  await user.type(screen.getByLabelText("Cloudflare account ID"), "a".repeat(32))
  await user.type(screen.getByLabelText("Existing tunnel ID"), "1".repeat(32))
  await user.type(screen.getByLabelText("Zone ID"), "b".repeat(32))
  await user.type(tokenInput, "cloudflare-token-secret")
  await user.click(screen.getByRole("button", { name: "Validate token" }))

  await waitFor(() => expect(api.authorizeCloudflare).toHaveBeenCalledWith({
    api_token: "cloudflare-token-secret", account_id: "a".repeat(32), tunnel_id: "1".repeat(32),
  }))
  await waitFor(() => expect(screen.queryByLabelText(/API token/i)).not.toBeInTheDocument())
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(document.body.textContent).not.toContain("cloudflare-token-secret")
})

test("clears a rejected token without retaining it in the mutation cache", async () => {
  const user = userEvent.setup()
  vi.mocked(api.authorizeCloudflare).mockRejectedValue(new Error("Token validation failed"))
  const { client } = renderPage()

  const tokenInput = await screen.findByLabelText(/API token/i)
  await user.type(screen.getByLabelText("Cloudflare account ID"), "a".repeat(32))
  await user.type(screen.getByLabelText("Existing tunnel ID"), "1".repeat(32))
  await user.type(screen.getByLabelText("Zone ID"), "b".repeat(32))
  await user.type(tokenInput, "rejected-cloudflare-token")
  await user.click(screen.getByRole("button", { name: "Validate token" }))

  await waitFor(() => expect(tokenInput).toHaveValue(""))
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(document.body.textContent).not.toContain("rejected-cloudflare-token")
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
    connections: [
      {
        id: "connection-id",
        provider: "cloudflare",
        external_id: "tunnel-id",
        label: "Cloudflare Tunnel",
        status: "connected",
        account_id: "a".repeat(32),
        public_metadata: { origin: "http://lnswitchboard:21212" },
        last_error: null,
        created_at: "2026-08-04T00:00:00Z",
        updated_at: "2026-08-04T00:00:00Z",
        domains: [],
      },
    ],
  })
  vi.mocked(api.cloudflareSetup).mockResolvedValue({ ...setup, available: false })

  renderPage()

  const heading = await screen.findByRole("heading", { name: "Cloudflare Tunnel" })
  expect(heading.closest('[data-slot="card"]')).not.toHaveAttribute("aria-disabled")
  expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled()
  expect(screen.getByRole("button", { name: "Disconnect" })).toBeEnabled()
})

test("collects explicit IDs and provisions the selected hostname on the existing tunnel", async () => {
  const user = userEvent.setup()
  vi.mocked(api.authorizeCloudflare).mockResolvedValue({ accounts: [] })
  vi.mocked(api.provisionCloudflare).mockResolvedValue({
    id: "connection-id",
    provider: "cloudflare",
    external_id: "tunnel-id",
    label: "Cloudflare Tunnel",
    status: "provisioning",
    account_id: "a".repeat(32),
    public_metadata: { origin: "http://lnswitchboard:21212" },
    last_error: null,
    created_at: "2026-08-04T00:00:00Z",
    updated_at: "2026-08-04T00:00:00Z",
    domains: [
      {
        hostname: "pay.example.com",
        status: "pending",
        zone_id: "b".repeat(32),
        external_id: "dns-id",
        last_error: null,
      },
    ],
  })

  renderPage()

  await user.type(await screen.findByLabelText("Cloudflare account ID"), "a".repeat(32))
  await user.type(screen.getByLabelText("Existing tunnel ID"), "1".repeat(32))
  await user.type(screen.getByLabelText("Zone ID"), "b".repeat(32))
  await user.type(screen.getByLabelText(/API token/i), "cloudflare-token-secret")
  await user.click(screen.getByRole("button", { name: "Validate token" }))
  await screen.findByRole("button", { name: "Configure existing tunnel" })
  await user.type(screen.getByLabelText("Public hostname"), "pay.example.com")
  await user.click(screen.getByRole("button", { name: "Configure existing tunnel" }))

  await waitFor(() => {
    expect(vi.mocked(api.provisionCloudflare).mock.calls[0]?.[0]).toEqual({
      account_id: "a".repeat(32),
      tunnel_id: "1".repeat(32),
      zone_id: "b".repeat(32),
      hostname: "pay.example.com",
    })
  })
  expect(api.cloudflareAuthorization).toHaveBeenCalled()
  expect(document.body.textContent).not.toContain("cloudflare-token-secret")
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
