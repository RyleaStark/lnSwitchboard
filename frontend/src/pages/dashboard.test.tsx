import { render, screen, within } from "@testing-library/react"

import { DashboardChart } from "@/pages/dashboard"

class ResizeObserverStub implements ResizeObserver {
  private readonly callback: ResizeObserverCallback

  constructor(callback: ResizeObserverCallback) {
    this.callback = callback
  }

  disconnect() {}

  observe(target: Element) {
    Object.defineProperties(target, {
      clientWidth: { configurable: true, value: 640 },
      clientHeight: { configurable: true, value: 280 },
    })
    this.callback([], this)
  }

  unobserve() {}
}

vi.stubGlobal("ResizeObserver", ResizeObserverStub)
Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: vi.fn(() => null),
})

const activity = [
  {
    date: "2026-08-02",
    sats: 1200,
    paid: 2,
    created: 4,
    pending: 1,
    settled: 2,
    expired: 1,
  },
  {
    date: "2026-08-03",
    sats: 2400,
    paid: 3,
    created: 5,
    pending: 1,
    settled: 3,
    expired: 1,
  },
]

describe("dashboard invoice activity", () => {
  it("shows every invoice state together on one chart", async () => {
    render(<DashboardChart activity={activity} />)

    expect(screen.queryByRole("tab")).not.toBeInTheDocument()
    const chart = await screen.findByRole("img", {
      name: "Invoice states and sats received over the last 14 days",
    })
    expect(chart).toHaveAttribute("data-chart-stack-type", "stacked")
    expect(chart).toHaveAttribute(
      "data-chart-series",
      "pending,settled,expired,sats"
    )
    expect(chart).toHaveAttribute("data-chart-secondary-series", "sats")
    expect(chart).toHaveAttribute("data-chart-series-kinds", "sats:line")
    expect(chart).toHaveAttribute("data-chart-line-glow-widths", "sats:4")
    const primaryDomain = chart.getAttribute("data-chart-primary-domain")
    const secondaryDomain = chart.getAttribute("data-chart-secondary-domain")
    expect(primaryDomain).not.toBeNull()
    expect(secondaryDomain).not.toBeNull()
    const primaryMax = Number(primaryDomain?.split(",").at(-1))
    const secondaryMax = Number(secondaryDomain?.split(",").at(-1))
    expect(primaryMax).toBeGreaterThanOrEqual(5)
    expect(primaryMax).toBeLessThan(100)
    expect(secondaryMax).toBeGreaterThanOrEqual(2400)

    const legend = screen.getByRole("list")
    expect(within(legend).getByText("Pending")).toBeInTheDocument()
    expect(within(legend).getByText("Paid")).toBeInTheDocument()
    expect(within(legend).getByText("Expired")).toBeInTheDocument()
    expect(within(legend).getByText("Sats received")).toBeInTheDocument()

    const table = screen.getByRole("table", {
      name: "Invoice states and sats received over the last 14 days",
    })
    expect(
      within(table).getByRole("row", {
        name: "2026-08-03 5 1 3 1 2,400",
      })
    ).toBeInTheDocument()
  })
})
