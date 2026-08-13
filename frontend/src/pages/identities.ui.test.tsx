import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { vi } from "vitest"

import { api } from "@/lib/api"
import { IdentitiesPage } from "@/pages/identities"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: {
    identities: vi.fn(),
    createIdentity: vi.fn(),
    updateIdentity: vi.fn(),
    deleteIdentity: vi.fn(),
  },
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <IdentitiesPage />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.identities).mockResolvedValue({
    items: [{
      id: "identity-1",
      local_part: "alice",
      domain: "example.com",
      identifier: "alice@example.com",
      npub: "npub123",
      pubkey_hex: "a".repeat(64),
      relays: ["wss://relay.example.com"],
    }],
  })
})

test("renders mappings directly on the page with search left of Add", async () => {
  renderPage()

  const pageHeading = screen.getByRole("heading", { name: "Nostr Identities" })
  expect(pageHeading.closest('[data-slot="card"]')).toBeNull()
  expect(screen.queryByRole("heading", { name: "Nostr mappings" })).not.toBeInTheDocument()
  expect(screen.queryByText("1 mapping")).not.toBeInTheDocument()
  expect((await screen.findAllByText("alice@example.com")).length).toBeGreaterThan(0)

  const search = screen.getByRole("textbox", { name: "Search mappings" })
  const add = screen.getByRole("button", { name: "Add mapping" })
  expect(search.compareDocumentPosition(add) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
})

test("keeps the flattened search behavior accessible", async () => {
  const user = userEvent.setup()
  renderPage()
  await screen.findAllByText("alice@example.com")

  await user.type(screen.getByRole("textbox", { name: "Search mappings" }), "missing")
  expect(screen.getByText("No matching mappings")).toBeVisible()
})
