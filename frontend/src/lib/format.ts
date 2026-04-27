import type { Channel, InvoiceEvent } from "@/lib/api"

export type InvoiceRecipientParts = {
  recipient: string
  taggedRecipient: string
  tag: string | null
}

export function formatNumber(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-"
  return new Intl.NumberFormat().format(value)
}

export function formatSats(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-"
  return `${formatNumber(Math.round(value))} sats`
}

export function formatMsatAsSats(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-"
  return formatSats(value / 1000)
}

export function formatTimestamp(value?: string | null): { display: string; iso: string } | null {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  const iso = date.toISOString()
  return {
    display: formatDateForDisplay(date, iso),
    iso,
  }
}

function formatDateForDisplay(date: Date, iso: string): string {
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      timeZoneName: "short",
    }).format(date)
  } catch {
    return iso.replace("T", " ").replace(/\.\d{3}Z$/, " UTC")
  }
}

export function shortHash(value?: string | null, prefix = 8, suffix = 6): string {
  const trimmed = value?.trim()
  if (!trimmed) return "-"
  if (trimmed.length <= prefix + suffix + 3) return trimmed
  return `${trimmed.slice(0, prefix)}...${trimmed.slice(-suffix)}`
}

export function normalizeDomainInput(value: string): string {
  return value.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0]?.split(":")[0] ?? ""
}

export function invoiceRecipient(invoice: InvoiceEvent): string {
  return invoiceRecipientParts(invoice).recipient
}

export function invoiceRecipientParts(invoice: InvoiceEvent): InvoiceRecipientParts {
  const lnAddress = invoiceDetailString(invoice, "ln_address")
  const addressParts = splitInvoiceAddress(lnAddress)
  const usernameRaw = invoiceDetailString(invoice, "username_raw")
  const username = invoice.username?.trim()
  const domain = invoice.domain?.trim() || addressParts.domain
  const localParts = splitInvoiceLocalPart(usernameRaw || addressParts.local || username)
  const tag = localParts.tag || invoiceDetailString(invoice, "tag")
  const localPart = localParts.local || username || addressParts.local
  const recipient = localPart && domain ? `${localPart}@${domain}` : localPart || domain || "-"
  const taggedRecipient = tag && localPart ? `${localPart}+${tag}${domain ? `@${domain}` : ""}` : recipient

  return {
    recipient,
    taggedRecipient,
    tag,
  }
}

function invoiceDetailString(invoice: InvoiceEvent, key: string): string | null {
  const details = invoice.details
  if (!details || typeof details !== "object" || Array.isArray(details)) return null
  const value = details[key]
  if (typeof value !== "string") return null
  const trimmed = value.trim()
  return trimmed || null
}

function splitInvoiceAddress(value?: string | null): { local: string | null; domain: string | null } {
  const trimmed = value?.trim()
  if (!trimmed) return { local: null, domain: null }
  const atIndex = trimmed.lastIndexOf("@")
  if (atIndex <= 0 || atIndex === trimmed.length - 1) return { local: trimmed, domain: null }
  return {
    local: trimmed.slice(0, atIndex),
    domain: trimmed.slice(atIndex + 1),
  }
}

function splitInvoiceLocalPart(value?: string | null): { local: string | null; tag: string | null } {
  const trimmed = value?.trim()
  if (!trimmed) return { local: null, tag: null }
  const plusIndex = trimmed.indexOf("+")
  if (plusIndex <= 0 || plusIndex === trimmed.length - 1) return { local: trimmed, tag: null }
  return {
    local: trimmed.slice(0, plusIndex),
    tag: trimmed.slice(plusIndex + 1),
  }
}

export function invoiceAmountSats(invoice: InvoiceEvent): number | null {
  if (typeof invoice.amount_sat === "number" && Number.isFinite(invoice.amount_sat)) return invoice.amount_sat
  if (typeof invoice.amount_msat === "number" && Number.isFinite(invoice.amount_msat)) return Math.round(invoice.amount_msat / 1000)
  return null
}

export function channelPeer(channel: Channel): string {
  return (
    normalizedChannelLabel(channel.peer_alias) ??
    normalizedChannelLabel(channel.alias) ??
    channelPeerIdentifier(channel, { compact: true }) ??
    "Unknown peer"
  )
}

export function channelPeerIdentifier(channel: Channel, options: { compact?: boolean } = {}): string | null {
  for (const value of [channel.remote_pubkey, channel.channel_id, channel.chan_id, channel.channel_point]) {
    if (value === null || value === undefined) continue
    const identifier = String(value).trim()
    if (identifier) return options.compact ? shortHash(identifier, 16, 8) : identifier
  }
  return null
}

function normalizedChannelLabel(value?: string | null): string | null {
  const trimmed = value?.trim()
  return trimmed || null
}

export function receivableCapacity(channel: Channel): number {
  if (typeof channel.receiving_capacity_sat === "number") return channel.receiving_capacity_sat
  if (typeof channel.remote_balance_sat === "number") return channel.remote_balance_sat
  return 0
}

export function sendableCapacity(channel: Channel): number {
  if (typeof channel.sendable_capacity_sat === "number") return channel.sendable_capacity_sat
  if (typeof channel.sendable_balance_sat === "number") return channel.sendable_balance_sat
  if (typeof channel.local_balance_sat === "number") return channel.local_balance_sat
  return 0
}

export function reserveTotal(channel: Channel): number {
  return (channel.local_chan_reserve_sat || 0) + (channel.remote_chan_reserve_sat || 0)
}

export async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value)
}
