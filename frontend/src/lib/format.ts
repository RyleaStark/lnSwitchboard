import type { Channel, InvoiceEvent } from "@/lib/api"

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
  return {
    display: new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
      timeZoneName: "short",
    }).format(date),
    iso: date.toISOString(),
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
  const username = invoice.username?.trim()
  const domain = invoice.domain?.trim()
  if (username && domain) return `${username}@${domain}`
  return username || domain || "-"
}

export function invoiceAmountSats(invoice: InvoiceEvent): number | null {
  if (typeof invoice.amount_sat === "number" && Number.isFinite(invoice.amount_sat)) return invoice.amount_sat
  if (typeof invoice.amount_msat === "number" && Number.isFinite(invoice.amount_msat)) return Math.round(invoice.amount_msat / 1000)
  return null
}

export function channelPeer(channel: Channel): string {
  return channel.alias || String(channel.chan_id || channel.channel_point || channel.remote_pubkey || "Unknown peer")
}

export function receivableCapacity(channel: Channel): number {
  if (typeof channel.receiving_capacity_sat === "number") return channel.receiving_capacity_sat
  if (typeof channel.remote_balance_sat === "number") return channel.remote_balance_sat
  return 0
}

export function sendableCapacity(channel: Channel): number {
  if (typeof channel.sendable_capacity_sat === "number") return channel.sendable_capacity_sat
  if (typeof channel.local_balance_sat === "number") return channel.local_balance_sat
  return 0
}

export function reserveTotal(channel: Channel): number {
  return (channel.local_chan_reserve_sat || 0) + (channel.remote_chan_reserve_sat || 0)
}

export async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value)
}
