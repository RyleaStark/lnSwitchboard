import { fireEvent, render, screen } from "@testing-library/react"

import { CopyButton } from "@/components/common"

describe("CopyButton", () => {
  it("copies supplied text", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    })

    render(<CopyButton value="lnbc1example" />)
    const button = screen.getByRole("button", { name: /copy/i })
    expect(button).not.toBeDisabled()
    fireEvent.click(button)

    expect(writeText).toHaveBeenCalledWith("lnbc1example")
  })
})
