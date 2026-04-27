import { formatTimestamp } from "@/lib/format"

describe("formatTimestamp", () => {
  it("falls back when Intl rejects date formatting options", () => {
    const original = Intl.DateTimeFormat
    vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => {
      throw new TypeError("Invalid option : option")
    })

    expect(formatTimestamp("2026-04-27T12:34:56.000Z")).toEqual({
      display: "2026-04-27 12:34:56 UTC",
      iso: "2026-04-27T12:34:56.000Z",
    })

    Intl.DateTimeFormat = original
  })
})
