import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

import { DashboardChart } from "@/pages/dashboard"

class ResizeObserverStub implements ResizeObserver {
  disconnect() {}
  observe() {}
  unobserve() {}
}

vi.stubGlobal("ResizeObserver", ResizeObserverStub)
Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: vi.fn(() => null),
})

const activity = [
  { date: "2026-08-02", sats: 1200, paid: 2, created: 4 },
  { date: "2026-08-03", sats: 2400, paid: 3, created: 5 },
]

describe("dashboard chart metrics", () => {
  it("switches between routed sats, paid invoices, and created invoices", async () => {
    const user = userEvent.setup()
    render(<DashboardChart activity={activity} />)

    const sats = screen.getByRole("tab", { name: "Sats routed" })
    const paid = screen.getByRole("tab", { name: "Invoices paid" })
    const created = screen.getByRole("tab", { name: "Invoices created" })

    expect(sats).toHaveAttribute("aria-selected", "true")
    expect(screen.getByRole("tabpanel", { name: "Sats routed" })).toBeVisible()
    const satsTable = screen.getByRole("table", { name: "Sats routed over the last 14 days" })
    expect(within(satsTable).getByRole("row", { name: "2026-08-02 1,200 sats" })).toBeInTheDocument()

    await user.click(sats)
    await user.keyboard("{ArrowRight}")
    expect(paid).toHaveFocus()
    expect(paid).toHaveAttribute("aria-selected", "true")
    expect(screen.getByRole("tabpanel", { name: "Invoices paid" })).toBeVisible()
    const paidTable = screen.getByRole("table", { name: "Invoices paid over the last 14 days" })
    const paidRow = within(paidTable).getByRole("row", { name: "2026-08-03 3" })
    expect(within(paidRow).getByRole("cell", { name: "3" })).toBeInTheDocument()

    await user.click(created)
    expect(created).toHaveAttribute("aria-selected", "true")
    expect(screen.getByRole("tabpanel", { name: "Invoices created" })).toBeVisible()
    const createdTable = screen.getByRole("table", { name: "Invoices created over the last 14 days" })
    const createdRow = within(createdTable).getByRole("row", { name: "2026-08-03 5" })
    expect(within(createdRow).getByRole("cell", { name: "5" })).toBeInTheDocument()
  })
})
