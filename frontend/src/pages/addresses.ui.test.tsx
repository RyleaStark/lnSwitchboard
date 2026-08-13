import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { vi } from "vitest"

import { api } from "@/lib/api"
import { AddressesPage } from "@/pages/addresses"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: {
    addresses: vi.fn(),
    identities: vi.fn(),
    createAddress: vi.fn(),
    updateAddress: vi.fn(),
    deleteAddress: vi.fn(),
    validateForwardingAddress: vi.fn(),
  },
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <AddressesPage />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.addresses).mockResolvedValue({ items: [] })
  vi.mocked(api.identities).mockResolvedValue({ items: [] })
})

test("renders addresses directly on the page with one Add action", async () => {
  renderPage()

  const pageHeading = screen.getByRole("heading", { name: "LN Addresses" })
  expect(pageHeading.closest('[data-slot="card"]')).toBeNull()
  expect(screen.queryByRole("heading", { name: "Lightning Addresses" })).not.toBeInTheDocument()
  expect(screen.queryByText(/address overrides?/)).not.toBeInTheDocument()
  expect(await screen.findByText("No LN addresses yet")).toBeVisible()
  expect(screen.getAllByRole("button", { name: "Add address" })).toHaveLength(1)
  expect(screen.queryByRole("button", { name: "Add forwarding address" })).not.toBeInTheDocument()
  expect(screen.getByRole("textbox", { name: "Search addresses" })).toBeVisible()
})

test("starts address creation by choosing a local or forwarding route", async () => {
  const user = userEvent.setup()
  renderPage()

  await user.click(screen.getByRole("button", { name: "Add address" }))

  expect(screen.getByRole("dialog", { name: "Add an address" })).toBeVisible()
  expect(screen.getByRole("button", { name: "Add an address connected to this node" })).toBeVisible()
  expect(screen.getByRole("button", { name: "Add an address that forwards to another lightning address" })).toBeVisible()
  expect(screen.queryByLabelText("Local-part")).not.toBeInTheDocument()

  await user.click(screen.getByRole("button", { name: "Add an address connected to this node" }))
  expect(screen.getByRole("dialog", { name: "Add LN address" })).toBeVisible()
  expect(screen.getByLabelText("Local-part")).toBeVisible()
})

test("opens the existing forwarding form from the unified Add flow", async () => {
  const user = userEvent.setup()
  renderPage()

  await user.click(screen.getByRole("button", { name: "Add address" }))
  await user.click(screen.getByRole("button", { name: "Add an address that forwards to another lightning address" }))

  expect(screen.getByRole("dialog", { name: "Add forwarding address" })).toBeVisible()
  expect(screen.getByLabelText("Forward to LN Address")).toBeVisible()
})
