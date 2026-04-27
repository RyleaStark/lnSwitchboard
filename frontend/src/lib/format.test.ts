import type { InvoiceEvent } from "@/lib/api"

import {
  channelPeer,
  channelPeerIdentifier,
  formatTimestamp,
  invoiceRecipient,
  invoiceRecipientParts,
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
