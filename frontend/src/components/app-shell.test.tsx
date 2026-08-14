import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, Route, Routes } from "react-router"

import { AppShell } from "@/components/app-shell"

class ResizeObserverStub implements ResizeObserver {
  disconnect() {}
  observe() {}
  unobserve() {}
}

vi.stubGlobal("ResizeObserver", ResizeObserverStub)
vi.stubGlobal("matchMedia", vi.fn().mockImplementation((query: string) => ({
  addEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
  matches: false,
  media: query,
  onchange: null,
  removeEventListener: vi.fn(),
})))

vi.mock("@/lib/api", () => ({
  api: {
    authStatus: vi.fn().mockResolvedValue({ configured: true }),
    health: vi.fn().mockResolvedValue({ status: "ok" }),
    lndStatus: vi.fn().mockResolvedValue({ connected: true, tls_status: "valid" }),
    version: vi.fn().mockResolvedValue({ version: "test" }),
  },
}))

function renderAppShell() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<div>Dashboard page</div>} />
            <Route path="invoices/" element={<div>Invoices page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe("AppShell scrolling", () => {
  it("keeps the shell at the viewport while the content pane scrolls", () => {
    const { container } = renderAppShell()

    expect(container.querySelector('[data-slot="sidebar-wrapper"]')).toHaveClass(
      "h-svh",
      "min-h-0",
      "overflow-hidden",
    )
    expect(container.querySelector('[data-slot="sidebar-inset"]')).toHaveClass(
      "min-h-0",
      "overflow-y-auto",
      "overscroll-y-contain",
    )
  })
})

describe("AppShell mobile navigation", () => {
  beforeEach(() => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 500,
    })
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        addEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
        matches: true,
        media: query,
        onchange: null,
        removeEventListener: vi.fn(),
      })),
    })
  })

  it("keeps bottom breathing room in the compact header and clips horizontal overflow", () => {
    const { container } = renderAppShell()
    const header = container.querySelector("header")
    const inset = container.querySelector('[data-slot="sidebar-inset"]')

    expect(header).toHaveClass("min-h-14", "h-auto", "pt-2", "pb-3")
    expect(inset).toHaveClass("min-w-0", "overflow-x-hidden")
  })

  it("closes the drawer after selecting a navigation destination", async () => {
    const user = userEvent.setup()
    renderAppShell()

    await user.click(screen.getByRole("button", { name: "Open navigation" }))
    expect(screen.getByRole("dialog", { name: "Sidebar" })).toBeVisible()

    await user.click(screen.getByRole("link", { name: "Invoices" }))

    expect(await screen.findByText("Invoices page")).toBeVisible()
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Sidebar" })).not.toBeInTheDocument()
    })
  })
})
