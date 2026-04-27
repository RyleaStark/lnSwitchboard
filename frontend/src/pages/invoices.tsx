import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { ChevronRightIcon, EyeIcon, SearchIcon } from "lucide-react"

import { CodeBlock, CopyButton, EmptyPanel, LoadingRows, PageError, PageHeader, Timestamp } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Channel, type InvoiceEvent, type JsonValue } from "@/lib/api"
import { formatNumber, formatSats, invoiceAmountSats, invoiceRecipientParts, shortHash } from "@/lib/format"

const PAGE_SIZE = 10

export function InvoicesPage() {
  const [query, setQuery] = useState("")
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<InvoiceEvent | null>(null)
  const invoices = useQuery({
    queryKey: ["invoices", page, query],
    queryFn: () => api.invoices(page, PAGE_SIZE, query),
    refetchInterval: 10_000,
  })
  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: api.channels,
    enabled: Boolean(selected),
    refetchInterval: selected ? 10_000 : false,
  })

  const items = invoices.data?.items ?? []

  return (
    <>
      <PageHeader
        eyebrow="Invoice ledger"
        title="Invoices"
        description="Review generated invoices, settlement status, payment hashes, expiry windows, and raw payment requests."
      />
      <Card>
        <CardHeader className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <CardTitle>Lightning invoices</CardTitle>
            <CardDescription>{paginationLabel(invoices.data, query, "invoice")}</CardDescription>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="relative">
              <SearchIcon className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value)
                  setPage(1)
                }}
                className="pl-8 sm:w-72"
                placeholder="Search invoices"
              />
            </div>
            <Pager page={page} totalPages={invoices.data?.total_pages ?? 0} setPage={setPage} />
          </div>
        </CardHeader>
        <CardContent>
          {invoices.isLoading ? <LoadingRows /> : null}
          {invoices.isError ? <PageError message="Unable to load invoices." /> : null}
          {!invoices.isLoading && !invoices.isError && items.length === 0 ? (
            <EmptyPanel title={query ? "No matching invoices" : "No invoices yet"} description="Invoices appear after wallets request an LNURL invoice." />
          ) : null}
          {items.length ? (
            <>
              <div className="hidden overflow-hidden rounded-md border md:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Created</TableHead>
                      <TableHead>Recipient</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>Payment hash</TableHead>
                      <TableHead className="text-right">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((invoice) => (
                      <TableRow key={invoice.id}>
                        <TableCell><Timestamp value={invoice.created_at} /></TableCell>
                        <TableCell className="max-w-72"><Recipient invoice={invoice} /></TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <StatusBadge status={invoice.status} />
                            <span>{formatSats(invoiceAmountSats(invoice) ?? undefined)}</span>
                          </div>
                        </TableCell>
                        <TableCell><code className="font-mono text-xs">{shortHash(invoice.payment_hash)}</code></TableCell>
                        <TableCell className="text-right">
                          <Button type="button" variant="outline" size="sm" onClick={() => setSelected(invoice)}>
                            <EyeIcon data-icon="inline-start" />
                            View
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-3 md:hidden">
                {items.map((invoice) => (
                  <Card key={invoice.id}>
                    <CardHeader>
                      <CardTitle className="min-w-0 text-base"><Recipient invoice={invoice} /></CardTitle>
                      <CardDescription><Timestamp value={invoice.created_at} /></CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-3">
                      <div className="flex items-center justify-between gap-3">
                        <StatusBadge status={invoice.status} />
                        <span className="font-medium">{formatSats(invoiceAmountSats(invoice) ?? undefined)}</span>
                      </div>
                      <code className="truncate font-mono text-xs">{invoice.payment_hash || "-"}</code>
                      <Button type="button" variant="outline" size="sm" onClick={() => setSelected(invoice)}>
                        <EyeIcon data-icon="inline-start" />
                        View details
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
      <InvoiceDetails
        channels={channels.data?.channels ?? []}
        invoice={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </>
  )
}

function InvoiceDetails({
  channels,
  invoice,
  onOpenChange,
}: {
  channels: Channel[]
  invoice: InvoiceEvent | null
  onOpenChange: (open: boolean) => void
}) {
  const settlementHtlcs = invoice ? invoiceSettlementHtlcs(invoice) : []
  return (
    <Dialog open={Boolean(invoice)} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden sm:max-w-3xl">
        <DialogHeader className="min-w-0 pr-10">
          <DialogTitle className="break-words">{invoice ? `Invoice for ${invoiceRecipientParts(invoice).taggedRecipient}` : "Invoice details"}</DialogTitle>
          <DialogDescription>Settlement, expiry, hash, and payment request details.</DialogDescription>
        </DialogHeader>
        {invoice ? (
          <div className="flex min-h-0 min-w-0 flex-col gap-5 overflow-x-hidden overflow-y-auto pr-1">
            <div className="grid min-w-0 gap-3 sm:grid-cols-2">
              <Detail label="Status"><StatusBadge status={invoice.status} /></Detail>
              <Detail label="Amount">{formatSats(invoiceAmountSats(invoice) ?? undefined)}</Detail>
              <Detail label="Created"><Timestamp value={invoice.created_at} /></Detail>
              <Detail label="Expires"><Timestamp value={invoice.expires_at} fallback={invoice.expired ? "Expired" : "-"} /></Detail>
              <Detail label="Next check"><Timestamp value={invoice.next_check_at} /></Detail>
              <Detail label="Settled"><Timestamp value={invoice.settled_at} fallback={invoice.settled ? "Unknown" : "-"} /></Detail>
            </div>
            {invoice.settled ? <SettlementPath channels={channels} htlcs={settlementHtlcs} /> : null}
            <div className="flex min-w-0 flex-col gap-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">Payment hash</span>
                <CopyButton value={invoice.payment_hash} />
              </div>
              <CodeBlock>{invoice.payment_hash || "-"}</CodeBlock>
            </div>
            <div className="flex min-w-0 flex-col gap-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">Payment request</span>
                <CopyButton value={invoice.payment_request} />
              </div>
              <CodeBlock>{invoice.payment_request || "-"}</CodeBlock>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-md border bg-muted/20 p-3">
      <dt className="text-xs font-medium uppercase tracking-normal text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-sm">{children}</dd>
    </div>
  )
}

function StatusBadge({ status }: { status?: string }) {
  const normalized = status === "settled" || status === "expired" || status === "pending" || status === "forwarded" ? status : "unknown"
  const variant = normalized === "settled" ? "default" : normalized === "expired" ? "destructive" : "secondary"
  return <Badge variant={variant}>{normalized.charAt(0).toUpperCase() + normalized.slice(1)}</Badge>
}

function Recipient({ invoice }: { invoice: InvoiceEvent }) {
  const parts = invoiceRecipientParts(invoice)
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      {parts.tag ? <Badge variant="secondary" className="shrink-0 font-mono">{parts.tag}</Badge> : null}
      <span className="truncate">{parts.recipient}</span>
    </span>
  )
}

function SettlementPath({ channels, htlcs }: { channels: Channel[]; htlcs: SettledHtlc[] }) {
  const htlc = htlcs[0]
  const incomingChannel = htlc ? findChannelById(channels, htlc.chan_id) : undefined
  const incomingLabel = incomingChannel?.peer_alias || incomingChannel?.alias || (htlc ? `Channel ${htlc.chan_id}` : "Incoming channel unavailable")
  const incomingDetail = htlc?.amt_msat ? formatSats(Number(htlc.amt_msat) / 1000) : null

  return (
    <div className="flex min-w-0 flex-col gap-2">
      <span className="text-sm font-medium">Settlement path</span>
      <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-md border bg-muted/20 p-3 text-sm">
        <Badge variant="secondary">Previous hops hidden</Badge>
        <PathArrow />
        <span className="min-w-0 truncate font-medium">{incomingLabel}</span>
        <PathArrow />
        <span className="font-medium">This node</span>
      </div>
      <p className="text-xs text-muted-foreground">
        Lightning receivers can only see the incoming HTLC/channel; earlier payer route hops are hidden by onion routing.
        {incomingDetail ? ` Incoming amount: ${incomingDetail}.` : ""}
      </p>
    </div>
  )
}

function PathArrow() {
  return <ChevronRightIcon className="size-4 text-muted-foreground" />
}

type SettledHtlc = {
  chan_id: string
  amt_msat?: string | number | null
  state?: string | null
}

function invoiceSettlementHtlcs(invoice: InvoiceEvent): SettledHtlc[] {
  const invoiceDetails = invoiceDetailsObject(invoice)
  const htlcs = invoiceDetails?.htlcs
  if (!Array.isArray(htlcs)) return []
  return htlcs
    .map((value) => normalizeHtlc(value))
    .filter((htlc): htlc is SettledHtlc => Boolean(htlc))
    .filter((htlc) => !htlc.state || htlc.state === "SETTLED")
}

function invoiceDetailsObject(invoice: InvoiceEvent): Record<string, JsonValue> | null {
  const details = invoice.details
  if (!details || typeof details !== "object" || Array.isArray(details)) return null
  const invoiceDetails = details.invoice
  if (!invoiceDetails || typeof invoiceDetails !== "object" || Array.isArray(invoiceDetails)) return null
  return invoiceDetails
}

function normalizeHtlc(value: JsonValue): SettledHtlc | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null
  const chanId = value.chan_id
  if (chanId === null || chanId === undefined || chanId === "") return null
  return {
    chan_id: String(chanId),
    amt_msat: typeof value.amt_msat === "string" || typeof value.amt_msat === "number" ? value.amt_msat : null,
    state: typeof value.state === "string" ? value.state : null,
  }
}

function findChannelById(channels: Channel[], chanId: string): Channel | undefined {
  return channels.find((channel) => String(channel.channel_id || channel.chan_id || "") === chanId)
}

export function Pager({
  page,
  totalPages,
  setPage,
}: {
  page: number
  totalPages: number
  setPage: (page: number) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <Button type="button" variant="outline" size="sm" disabled={totalPages === 0 || page <= 1} onClick={() => setPage(page - 1)}>
        Previous
      </Button>
      <Badge variant="secondary">{totalPages > 0 ? `${page} / ${totalPages}` : "0"}</Badge>
      <Button type="button" variant="outline" size="sm" disabled={totalPages === 0 || page >= totalPages} onClick={() => setPage(page + 1)}>
        Next
      </Button>
    </div>
  )
}

export function paginationLabel(data: { total_items: number; total_pages: number; page: number } | undefined, query: string, noun: string) {
  if (!data) return "Loading..."
  if (data.total_items === 0) return query ? "No matches" : `No ${noun}s yet`
  if (data.total_pages <= 1) return `${formatNumber(data.total_items)} ${noun}${data.total_items === 1 ? "" : "s"}`
  return `Page ${data.page} of ${data.total_pages} - ${formatNumber(data.total_items)} ${noun}s`
}
