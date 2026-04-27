import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { EyeIcon, SearchIcon, Trash2Icon } from "lucide-react"
import { toast } from "sonner"

import { CodeBlock, EmptyPanel, LoadingRows, PageError, PageHeader, Timestamp } from "@/components/common"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type JsonValue, type RequestLog } from "@/lib/api"
import { formatMsatAsSats, requestLogRecipientParts } from "@/lib/format"
import { Pager, paginationLabel } from "@/pages/invoices"

const PAGE_SIZE = 10

export function LogsPage() {
  const queryClient = useQueryClient()
  const [query, setQuery] = useState("")
  const [page, setPage] = useState(1)
  const [details, setDetails] = useState<JsonValue | null>(null)
  const logs = useQuery({
    queryKey: ["logs", page, query],
    queryFn: () => api.logs(page, PAGE_SIZE, query),
    refetchInterval: 10_000,
  })
  const clearLogs = useMutation({
    mutationFn: api.clearLogs,
    onSuccess: async () => {
      toast.success("Logs cleared")
      setPage(1)
      await queryClient.invalidateQueries({ queryKey: ["logs"] })
      await queryClient.invalidateQueries({ queryKey: ["summary"] })
    },
  })
  const items = logs.data?.items ?? []

  return (
    <>
      <PageHeader
        eyebrow="Request trail"
        title="Request Logs"
        description="Search LNURL discovery, invoice, verification, and rate-limit events with raw JSON context when needed."
        action={
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" disabled={clearLogs.isPending}>
                <Trash2Icon data-icon="inline-start" />
                Clear logs
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Clear logs?</AlertDialogTitle>
                <AlertDialogDescription>This removes recent request log records from the UI store. This cannot be undone.</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => clearLogs.mutate()} disabled={clearLogs.isPending}>Clear logs</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        }
      />
      <Card>
        <CardHeader className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <CardTitle>Request activity</CardTitle>
            <CardDescription>{paginationLabel(logs.data, query, "log")}</CardDescription>
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
                placeholder="Search logs"
              />
            </div>
            <Pager page={page} totalPages={logs.data?.total_pages ?? 0} setPage={setPage} />
          </div>
        </CardHeader>
        <CardContent>
          {logs.isLoading ? <LoadingRows /> : null}
          {logs.isError ? <PageError message="Unable to load logs." /> : null}
          {!logs.isLoading && !logs.isError && items.length === 0 ? (
            <EmptyPanel title={query ? "No matching logs" : "No activity yet"} description="LNURL interactions will appear here as wallets call this switchboard." />
          ) : null}
          {items.length ? (
            <>
              <div className="hidden overflow-hidden rounded-md border lg:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Recipient</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>Event</TableHead>
                      <TableHead className="text-right">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((entry, index) => (
                      <LogTableRow key={`${entry.timestamp}-${index}`} entry={entry} onDetails={setDetails} />
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-3 lg:hidden">
                {items.map((entry, index) => (
                  <Card key={`${entry.timestamp}-${index}`}>
                    <CardHeader>
                      <CardTitle className="min-w-0 text-base"><Recipient entry={entry} /></CardTitle>
                      <CardDescription><Timestamp value={entry.timestamp} /></CardDescription>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-3">
                      <div className="flex items-center justify-between gap-3">
                        <EventBadge entry={entry} />
                        <LogAmount entry={entry} />
                      </div>
                      {entry.message ? <p className="text-sm text-muted-foreground">{entry.message}</p> : null}
                      <Button type="button" variant="outline" size="sm" disabled={!entry.details} onClick={() => setDetails(entry.details ?? null)}>
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
      <Dialog open={details !== null} onOpenChange={(open) => !open && setDetails(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Log details</DialogTitle>
            <DialogDescription>Raw structured context stored for this request.</DialogDescription>
          </DialogHeader>
          <CodeBlock>{JSON.stringify(details, null, 2)}</CodeBlock>
        </DialogContent>
      </Dialog>
    </>
  )
}

function LogTableRow({ entry, onDetails }: { entry: RequestLog; onDetails: (details: JsonValue | null) => void }) {
  return (
    <>
      <TableRow>
        <TableCell><Timestamp value={entry.timestamp} /></TableCell>
        <TableCell><Recipient entry={entry} /></TableCell>
        <TableCell><LogAmount entry={entry} /></TableCell>
        <TableCell><EventBadge entry={entry} /></TableCell>
        <TableCell className="text-right">
          <Button type="button" variant="outline" size="sm" disabled={!entry.details} onClick={() => onDetails(entry.details ?? null)}>
            <EyeIcon data-icon="inline-start" />
            View
          </Button>
        </TableCell>
      </TableRow>
      {entry.message ? (
        <TableRow>
          <TableCell colSpan={5} className="bg-muted/20 text-sm text-muted-foreground">
            <span className="font-medium text-foreground">Message:</span> {entry.message}
          </TableCell>
        </TableRow>
      ) : null}
    </>
  )
}

function Recipient({ entry }: { entry: RequestLog }) {
  const parts = requestLogRecipientParts(entry)
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      {parts.tag ? <Badge variant="secondary" className="shrink-0 font-mono">{parts.tag}</Badge> : null}
      <span className="truncate">{parts.recipient}</span>
    </span>
  )
}

function EventBadge({ entry }: { entry: RequestLog }) {
  const event = entry.event || "unknown"
  const status = entry.status || "ok"
  return (
    <span className="inline-flex items-center gap-2">
      <Badge variant={status === "error" ? "destructive" : "secondary"}>{event.replace(/_/g, " ")}</Badge>
      {status !== "ok" ? <span className="text-xs text-muted-foreground">{status}</span> : null}
    </span>
  )
}

function LogAmount({ entry }: { entry: RequestLog }) {
  const amount = entry.amount_msat ? formatMsatAsSats(entry.amount_msat) : "-"
  if (!isForwardedLog(entry)) return <span className="text-sm">{amount}</span>
  return (
    <span className="inline-flex flex-wrap items-center justify-end gap-2 text-sm">
      <Badge variant="secondary">Forwarded</Badge>
      <span>{amount}</span>
    </span>
  )
}

function isForwardedLog(entry: RequestLog): boolean {
  const details = entry.details
  return Boolean(details && typeof details === "object" && !Array.isArray(details) && details.forwarded === true)
}
