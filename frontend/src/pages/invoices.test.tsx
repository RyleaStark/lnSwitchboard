import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

import { Pager, paginationLabel } from "@/pages/invoices"

describe("pagination helpers", () => {
  it("formats multi-page labels", () => {
    expect(paginationLabel({ total_items: 21, total_pages: 3, page: 2 }, "", "invoice")).toBe(
      "Page 2 of 3 - 21 invoices",
    )
  })

  it("moves between pages with disabled edges", async () => {
    const user = userEvent.setup()
    const setPage = vi.fn()
    render(<Pager page={2} totalPages={3} setPage={setPage} />)

    await user.click(screen.getByRole("button", { name: /previous/i }))
    await user.click(screen.getByRole("button", { name: /next/i }))

    expect(setPage).toHaveBeenNthCalledWith(1, 1)
    expect(setPage).toHaveBeenNthCalledWith(2, 3)
  })
})
