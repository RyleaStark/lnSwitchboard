import type { InvoiceEvent, RequestLog } from "@/lib/api"

import {
  channelPeer,
  channelPeerIdentifier,
  copyText,
  formatTimestamp,
  invoiceRecipient,
  invoiceRecipientParts,
  requestLogRecipientParts,
  sendableCapacity,
} from "@/lib/format"

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

describe("copyText", () => {
  it("uses the textarea fallback on insecure origins", async () => {
    const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard")
    const secureContextDescriptor = Object.getOwnPropertyDescriptor(window, "isSecureContext")
    const execCommandDescriptor = Object.getOwnPropertyDescriptor(document, "execCommand")
    const writeText = vi.fn().mockResolvedValue(undefined)
    const execCommand = vi.fn().mockReturnValue(true)

    Object.defineProperty(window, "isSecureContext", {
      configurable: true,
      value: false,
    })
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    })
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: execCommand,
    })

    try {
      await copyText("lnswitchboard+tips@bigbones.net")

      expect(writeText).not.toHaveBeenCalled()
      expect(execCommand).toHaveBeenCalledWith("copy")
      expect(document.querySelector("textarea")).toBeNull()
    } finally {
      restoreDescriptor(navigator, "clipboard", clipboardDescriptor)
      restoreDescriptor(window, "isSecureContext", secureContextDescriptor)
      restoreDescriptor(document, "execCommand", execCommandDescriptor)
    }
  })
})

describe("channel formatting", () => {
  it("prefers LND peer aliases over channel identifiers", () => {
    expect(channelPeer({
      peer_alias: "Bargly",
      remote_pubkey: "b7bf3c5a1c69e470551a610564be88fc25c97c89c6541b2aae8b24b83a8cf258",
      channel_point: "abc:0",
    })).toBe("Bargly")
  })

  it("uses compact identifiers when an alias is unavailable", () => {
    expect(channelPeer({
      remote_pubkey: "b7bf3c5a1c69e470551a610564be88fc25c97c89c6541b2aae8b24b83a8cf258",
      channel_point: "abc:0",
    })).toBe("b7bf3c5a1c69e470...3a8cf258")
    expect(channelPeerIdentifier({
      remote_pubkey: "b7bf3c5a1c69e470551a610564be88fc25c97c89c6541b2aae8b24b83a8cf258",
    }, { compact: true })).toBe("b7bf3c5a1c69e470...3a8cf258")
  })

  it("uses backend sendable balance fields", () => {
    expect(sendableCapacity({ sendable_balance_sat: 1250, local_balance_sat: 3000 })).toBe(1250)
  })
})

describe("invoice recipient formatting", () => {
  it("splits plus tags from invoice detail metadata", () => {
    const invoice = invoiceFixture({
      username: "plex",
      domain: "bigbones.net",
      details: {
        username_raw: "plex+cf",
        tag: "cf",
        ln_address: "plex+cf@bigbones.net",
      },
    })

    expect(invoiceRecipientParts(invoice)).toEqual({
      recipient: "plex@bigbones.net",
      taggedRecipient: "plex+cf@bigbones.net",
      tag: "cf",
    })
    expect(invoiceRecipient(invoice)).toBe("plex@bigbones.net")
  })

  it("falls back to ln_address when username_raw is unavailable", () => {
    expect(invoiceRecipientParts(invoiceFixture({
      username: "plex",
      domain: null,
      details: {
        ln_address: "plex+cf@bigbones.net",
      },
    }))).toEqual({
      recipient: "plex@bigbones.net",
      taggedRecipient: "plex+cf@bigbones.net",
      tag: "cf",
    })
  })
})

describe("request log recipient formatting", () => {
  it("splits plus tags from log detail metadata", () => {
    const entry = requestLogFixture({
      username: "plex",
      domain: "bigbones.net",
      details: {
        username_raw: "plex+cf",
        tag: "cf",
        ln_address: "plex+cf@bigbones.net",
      },
    })

    expect(requestLogRecipientParts(entry)).toEqual({
      recipient: "plex@bigbones.net",
      taggedRecipient: "plex+cf@bigbones.net",
      tag: "cf",
    })
  })

  it("splits plus tags from the logged username when details are unavailable", () => {
    expect(requestLogRecipientParts(requestLogFixture({
      username: "plex+cf",
      domain: "bigbones.net",
    }))).toEqual({
      recipient: "plex@bigbones.net",
      taggedRecipient: "plex+cf@bigbones.net",
      tag: "cf",
    })
  })
})

function invoiceFixture(overrides: Partial<InvoiceEvent>): InvoiceEvent {
  return {
    id: 1,
    created_at: "2026-04-27T00:00:00.000Z",
    username: "plex",
    settled: false,
    expired: false,
    status: "pending",
    ...overrides,
  }
}

function requestLogFixture(overrides: Partial<RequestLog>): RequestLog {
  return {
    timestamp: "2026-04-27T00:00:00.000Z",
    username: "plex",
    ip: "127.0.0.1",
    event: "pay_request",
    ...overrides,
  }
}

function restoreDescriptor(target: object, key: string, descriptor: PropertyDescriptor | undefined) {
  if (descriptor) {
    Object.defineProperty(target, key, descriptor)
  } else {
    delete (target as Record<string, unknown>)[key]
  }
}
