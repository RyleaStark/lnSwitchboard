import { bytesToHex, macaroonStatusLabel } from "@/pages/settings"

describe("settings macaroon helpers", () => {
  it("converts binary macaroon bytes to hex", () => {
    expect(bytesToHex(new Uint8Array([0, 1, 15, 255]))).toBe("00010fff")
  })

  it("labels mounted and manual macaroon states", () => {
    expect(
      macaroonStatusLabel({
        configured: true,
        source: "file",
        manual_entry_allowed: false,
      }),
    ).toBe("Mounted file")

    expect(
      macaroonStatusLabel({
        configured: false,
        source: "manual",
        manual_entry_allowed: true,
      }),
    ).toBe("Not configured")
  })
})
