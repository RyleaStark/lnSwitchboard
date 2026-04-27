import { collectAddressPayload } from "@/pages/addresses"

describe("collectAddressPayload", () => {
  it("normalizes domain, numeric limits, nullable templates, and webhook URLs", () => {
    const payload = collectAddressPayload({
      local_part: "Alice",
      domain: "https://Example.COM/path",
      min_sats: "10.9",
      max_sats: "100",
      metadata_description: " Pay {ln_address} ",
      success_message: "",
      webhook_urls: "https://hooks.example/a\nhttps://hooks.example/a",
    })

    expect(payload).toEqual({
      local_part: "alice",
      domain: "example.com",
      min_sats: 10,
      max_sats: 100,
      metadata_description: "Pay {ln_address}",
      success_message: null,
      webhook_urls: ["https://hooks.example/a"],
    })
  })

  it("rejects max sats below min sats", () => {
    const result = collectAddressPayload({
      local_part: "alice",
      domain: "example.com",
      min_sats: "100",
      max_sats: "10",
      metadata_description: "",
      success_message: "",
      webhook_urls: "",
    })

    expect(result).toContain("Maximum sats")
  })
})
