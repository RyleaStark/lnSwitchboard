import { normalizeApiErrorDetail } from "@/lib/api"

describe("normalizeApiErrorDetail", () => {
  it("returns string details directly", () => {
    expect(normalizeApiErrorDetail("Invalid webhook URL")).toBe("Invalid webhook URL")
  })

  it("flattens FastAPI validation details", () => {
    expect(normalizeApiErrorDetail([{ msg: "local-part is required" }, { msg: "domain is required" }])).toBe(
      "local-part is required domain is required",
    )
  })

  it("unwraps nested detail objects", () => {
    expect(normalizeApiErrorDetail({ detail: [{ msg: "max_sats cannot be smaller" }] })).toBe(
      "max_sats cannot be smaller",
    )
  })
})
