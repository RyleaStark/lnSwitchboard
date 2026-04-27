import { collectAddressPayload, collectForwardingAddressPayload, isForwardingValidationCurrent } from "@/pages/addresses"

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

  it("requires current validation for forwarding addresses", () => {
    const form = {
      local_part: "Tips",
      domain: "https://Example.COM/path",
      forward_to: "Bones@WalletOfSatoshi.com",
    }

    expect(
      collectForwardingAddressPayload(form, {
        status: "idle",
        target: "",
        message: "",
      }),
    ).toContain("Validate")

    expect(
      collectForwardingAddressPayload(form, {
        status: "valid",
        target: "bones@walletofsatoshi.com",
        message: "Validated bones@walletofsatoshi.com",
      }),
    ).toEqual({
      local_part: "tips",
      domain: "example.com",
      routing_mode: "forward",
      forward_to: "bones@walletofsatoshi.com",
      min_sats: null,
      max_sats: null,
      metadata_description: null,
      success_message: null,
      webhook_urls: [],
    })
  })

  it("invalidates forwarding validation when the target changes", () => {
    expect(
      isForwardingValidationCurrent(
        {
          local_part: "tips",
          domain: "example.com",
          forward_to: "alice@example.com",
        },
        {
          status: "valid",
          target: "bones@walletofsatoshi.com",
          message: "Validated bones@walletofsatoshi.com",
        },
      ),
    ).toBe(false)
  })
})
