import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

import { TooltipProvider } from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import { DashboardPage } from "@/pages/dashboard"
import { InvoicesPage } from "@/pages/invoices"
import { LiquidityPage } from "@/pages/liquidity"
import { LogsPage } from "@/pages/logs"

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  api: {
    summary: vi.fn(),
    invoices: vi.fn(),
    channels: vi.fn(),
    logs: vi.fn(),
    clearLogs: vi.fn(),
  },
}))

function renderPage(page: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><TooltipProvider>{page}</TooltipProvider></QueryClientProvider>)
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.channels).mockResolvedValue({ channels: [], total_receiving_capacity_sat: 0 })
})

test("request activity leads directly to its controls and table without a parent card", async () => {
  vi.mocked(api.logs).mockResolvedValue({ page: 1, page_size: 10, total_items: 0, total_pages: 0, has_next: false, has_prev: false, items: [] })
  renderPage(<LogsPage />)

  const search = await screen.findByPlaceholderText("Search logs")
  expect(search.closest('[data-slot="card"]')).toBeNull()
  expect(screen.queryByText("Request activity")).not.toBeInTheDocument()
})

test("log details present readable fields before optional technical data", async () => {
  const user = userEvent.setup()
  vi.mocked(api.logs).mockResolvedValue({
    page: 1,
    page_size: 10,
    total_items: 1,
    total_pages: 1,
    has_next: false,
    has_prev: false,
    items: [{
      timestamp: "2026-08-13T12:00:00Z",
      username: "alice",
      ip: "192.0.2.1",
      event: "invoice_created",
      status: "ok",
      details: { payment_hash: "abc123", forwarded: true, nested_context: { attempt_count: 2 } },
    }],
  })
  renderPage(<LogsPage />)

  await user.click(await screen.findByRole("button", { name: "View" }))
  const dialog = screen.getByRole("dialog", { name: "Request details" })
  expect(within(dialog).getByText("Payment hash")).toBeVisible()
  expect(within(dialog).getByText("abc123")).toBeVisible()
  expect(within(dialog).getByText("Yes")).toBeVisible()
  const technical = within(dialog).getByText("Technical details")
  expect(technical.closest("details")).not.toHaveAttribute("open")
  expect(within(dialog).queryByText(/Raw structured context/)).not.toBeInTheDocument()
})

test("liquidity table follows the two summary columns without a redundant parent surface", async () => {
  vi.mocked(api.channels).mockResolvedValue({
    total_receiving_capacity_sat: 500,
    channels: [{ channel_id: "1", active: true, capacity_sat: 1000, local_balance_sat: 500, remote_balance_sat: 500 }],
  })
  renderPage(<LiquidityPage />)

  const table = await screen.findByRole("table")
  expect(table.closest('[data-slot="card"]')).toBeNull()
  expect(screen.queryByText("Inbound capacity by peer")).not.toBeInTheDocument()
  expect(screen.queryByText("Sorted by receivable capacity descending.")).not.toBeInTheDocument()
})

test("invoice controls and table are not wrapped in a parent card", async () => {
  vi.mocked(api.invoices).mockResolvedValue({ page: 1, page_size: 10, total_items: 0, total_pages: 0, has_next: false, has_prev: false, items: [] })
  renderPage(<InvoicesPage />)

  const search = await screen.findByPlaceholderText("Search invoices")
  expect(search.closest('[data-slot="card"]')).toBeNull()
  expect(screen.queryByText("Lightning invoices")).not.toBeInTheDocument()
})

test("dashboard omits the minted total badge", async () => {
  vi.mocked(api.summary).mockResolvedValue({
    connected_domains: 0,
    requests_24h: 0,
    requests_7d: 0,
    invoices_total: 3,
    invoices_paid: 0,
    invoices_paid_24h: 0,
    total_sats_routed: 0,
    sats_routed_7d: 0,
    invoice_activity: [],
  })
  renderPage(<DashboardPage />)

  expect(await screen.findByText("Invoice activity")).toBeVisible()
  expect(screen.queryByText(/minted total/i)).not.toBeInTheDocument()
})
