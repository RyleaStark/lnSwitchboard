import { bytesToHex, macaroonStatusLabel, preferredSettingsTab, visibleEnvSettings } from "@/pages/settings"

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

  it("prefers environment settings when the macaroon is configured", () => {
    expect(
      preferredSettingsTab({
        configured: true,
        source: "manual",
        manual_entry_allowed: true,
      }),
    ).toBe("env")

    expect(
      preferredSettingsTab({
        configured: false,
        source: "manual",
        manual_entry_allowed: true,
      }),
    ).toBe("auth")
  })

  it("hides deployment environment from user-facing settings", () => {
    expect(
      visibleEnvSettings([
        {
          key: "DEP_ENV",
          label: "Deployment Environment",
          description: "Internal deployment target",
          type: "text",
          category: "System",
          editable: false,
          value: "DOCKER",
        },
        {
          key: "RECENT_LOG_LIMIT",
          label: "Recent Log Buffer",
          description: "Maximum number of log entries retained in memory.",
          type: "number",
          category: "System",
          editable: true,
          value: "50",
        },
      ]).map((field) => field.key),
    ).toEqual(["RECENT_LOG_LIMIT"])
  })
})
