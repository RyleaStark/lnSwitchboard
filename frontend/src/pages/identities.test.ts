import { collectIdentityPayload } from "@/pages/identities"

describe("collectIdentityPayload", () => {
  it("normalizes identity form data", () => {
    expect(
      collectIdentityPayload({
        local_part: "Alice",
        domain: "https://Example.COM/profile",
        npub: "npub123",
        relays: "relay.example\nwss://relay2.example",
      }),
    ).toEqual({
      local_part: "alice",
      domain: "example.com",
      npub: "npub123",
      relays: ["relay.example", "wss://relay2.example"],
    })
  })

  it("requires identity essentials", () => {
    expect(collectIdentityPayload({ local_part: "", domain: "", npub: "", relays: "" })).toContain("required")
  })
})
