import { render, screen } from "@testing-library/react"

import { SettingsPage, EnvField } from "@/pages/settings"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import userEvent from "@testing-library/user-event"

it("makes machine client provisioning discoverable in Settings", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ settings: [], clients: [], manual_entry_allowed: true }))))
  render(<QueryClientProvider client={new QueryClient()}><SettingsPage /></QueryClientProvider>)
  await userEvent.click(screen.getByRole("tab", { name: "Machine clients" }))
  expect(screen.getByRole("button", { name: "Add client" })).toBeInTheDocument()
})


describe("environment setting fields", () => {
  it("renders backend-provided choices as a select instead of free text", () => {
    render(
      <EnvField
        field={{
          key: "PUBLIC_FALLBACK_MODE",
          label: "Other Public URLs",
          description: "Choose the fallback behavior.",
          type: "select",
          category: "Public Listener",
          editable: true,
          value: "reject",
          options: [
            { value: "reject", label: "Reject with an error" },
            { value: "redirect", label: "Redirect to another site" },
          ],
        }}
        value="reject"
        onChange={() => undefined}
      />,
    )

    expect(screen.getByRole("combobox", { name: "Other Public URLs" })).toHaveTextContent(
      "Reject with an error",
    )
    expect(screen.queryByRole("textbox", { name: "Other Public URLs" })).not.toBeInTheDocument()
  })
})
