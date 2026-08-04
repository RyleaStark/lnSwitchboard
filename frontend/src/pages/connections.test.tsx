import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
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
    ],
    connections: [],
  })
  vi.mocked(api.cloudflareSetup).mockResolvedValue(setup)
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
  await user.type(tokenInput, "cloudflare-token-secret")
  await user.click(screen.getByRole("button", { name: "Validate token" }))

  await waitFor(() => expect(api.authorizeCloudflare).toHaveBeenCalledWith("cloudflare-token-secret"))
  await waitFor(() => expect(screen.queryByLabelText(/API token/i)).not.toBeInTheDocument())
  expect(client.getMutationCache().getAll()).toHaveLength(0)
  expect(document.body.textContent).not.toContain("cloudflare-token-secret")
})

test("clears a rejected token without retaining it in the mutation cache", async () => {
  const user = userEvent.setup()
  vi.mocked(api.authorizeCloudflare).mockRejectedValue(new Error("Token validation failed"))
  const { client } = renderPage()

  const tokenInput = await screen.findByLabelText(/API token/i)
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

test("loads the short-lived token authorization and provisions the selected hostname", async () => {
  const user = userEvent.setup()
  vi.mocked(api.cloudflareAuthorization).mockResolvedValue({
    accounts: [
      {
        id: "a".repeat(32),
        name: "Example Account",
        zones: [{ id: "b".repeat(32), name: "example.com" }],
      },
    ],
  })
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

  await screen.findByText("Example Account")
  await user.type(screen.getByLabelText("Public hostname"), "pay.example.com")
  await user.click(screen.getByRole("button", { name: "Create tunnel" }))

  await waitFor(() => {
    expect(vi.mocked(api.provisionCloudflare).mock.calls[0]?.[0]).toEqual({
      account_id: "a".repeat(32),
      zone_id: "b".repeat(32),
      hostname: "pay.example.com",
    })
  })
  expect(api.cloudflareAuthorization).toHaveBeenCalled()
  expect(document.body.textContent).not.toContain("cloudflare-token-secret")
})
