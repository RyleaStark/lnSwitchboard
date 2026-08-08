import { useQuery } from "@tanstack/react-query"
import { BadgeDollarSignIcon, GlobeIcon, ListChecksIcon, ReceiptTextIcon } from "lucide-react"

import { EmptyPanel, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Area, Line } from "@/components/dither-kit/area"
import { AreaChart } from "@/components/dither-kit/area-chart"
import { BlockLegend } from "@/components/dither-kit/block-legend"
import { Grid } from "@/components/dither-kit/grid"
import { Tooltip } from "@/components/dither-kit/tooltip"
import { XAxis } from "@/components/dither-kit/x-axis"
import { YAxis } from "@/components/dither-kit/y-axis"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { api, type SummaryStats } from "@/lib/api"
import { formatNumber, formatSats } from "@/lib/format"

const invoiceStateConfig = {
  pending: { label: "Pending", color: "orange" },
  settled: { label: "Paid", color: "green" },
  expired: { label: "Expired", color: "red" },
  sats: { label: "Sats received", color: "blue", axis: "secondary" },
} as const

export function DashboardPage() {
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.summary(new Date().getTimezoneOffset()),
    refetchInterval: 10_000,
  })

  return (
    <>
      <PageHeader
        title="Dashboard"
      />
      {summary.isLoading ? <LoadingRows rows={3} /> : null}
      {summary.isError ? <PageError message="Unable to load dashboard metrics." onRetry={() => void summary.refetch()} retrying={summary.isFetching} /> : null}
      {summary.data ? (
        <div className="flex flex-col gap-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard icon={<GlobeIcon />} label="Connected domains" value={formatNumber(summary.data.connected_domains)} />
            <MetricCard icon={<ListChecksIcon />} label="Requests 24h" value={formatNumber(summary.data.requests_24h)} note={`${formatNumber(summary.data.requests_7d)} in 7d`} />
            <MetricCard icon={<ReceiptTextIcon />} label="Invoices paid" value={formatNumber(summary.data.invoices_paid)} note={`${formatNumber(summary.data.invoices_paid_24h)} in 24h`} />
            <MetricCard icon={<BadgeDollarSignIcon />} label="Sats routed" value={formatSats(summary.data.total_sats_routed)} note={`${formatSats(summary.data.sats_routed_7d)} in 7d`} />
          </div>
          <Card>
            <CardHeader className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
              <div>
                <CardTitle>Invoice activity</CardTitle>
                <CardDescription>Invoice states by creation day with sats received by settlement day over the last 14 days.</CardDescription>
              </div>
              <Badge variant="secondary">{formatNumber(summary.data.invoices_total)} minted total</Badge>
            </CardHeader>
            <CardContent>
              {summary.data.invoice_activity.some((item) => item.sats > 0 || item.paid > 0 || item.created > 0) ? (
                <DashboardChart activity={summary.data.invoice_activity} />
              ) : (
                <EmptyPanel title="No invoice activity yet" description="Pending, paid, and expired invoices will render here as wallets use generated invoices." />
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </>
  )
}

export function DashboardChart({ activity }: { activity: SummaryStats["invoice_activity"] }) {
  return (
    <div className="space-y-3">
      <BlockLegend config={invoiceStateConfig} />
      <div className="h-[280px] w-full pt-2">
        <AreaChart
          data={activity}
          config={invoiceStateConfig}
          stackType="stacked"
          margins={{ left: 40, right: 48, top: 20, bottom: 24 }}
          bloom="aura"
          ariaLabel="Invoice states and sats received over the last 14 days"
        >
          <Grid horizontal />
          <XAxis dataKey="date" maxTicks={4} />
          <YAxis tickCount={4} />
          <YAxis axis="secondary" tickCount={4} tickFormatter={formatCompactNumber} />
          <Tooltip
            labelKey="date"
            valueFormatter={(value, name) =>
              name === "sats" ? formatSats(value) : formatNumber(value)
            }
          />
          <Area dataKey="pending" variant="dotted" />
          <Area dataKey="settled" variant="gradient" />
          <Area dataKey="expired" variant="hatched" />
          <Line dataKey="sats" variant="solid" lineGlowWidth={4} />
        </AreaChart>
      </div>
      <table className="sr-only">
        <caption>Invoice states and sats received over the last 14 days</caption>
        <thead>
          <tr>
            <th scope="col">Date</th>
            <th scope="col">Created</th>
            <th scope="col">Pending</th>
            <th scope="col">Paid</th>
            <th scope="col">Expired</th>
            <th scope="col">Sats received</th>
          </tr>
        </thead>
        <tbody>
          {activity.map((item) => (
            <tr key={item.date}>
              <th scope="row">{item.date}</th>
              <td>{formatNumber(item.created)}</td>
              <td>{formatNumber(item.pending)}</td>
              <td>{formatNumber(item.settled)}</td>
              <td>{formatNumber(item.expired)}</td>
              <td>{formatNumber(item.sats)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function formatCompactNumber(value: number): string {
  return new Intl.NumberFormat(undefined, {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value)
}

function MetricCard({
  icon,
  label,
  value,
  note,
}: {
  icon: React.ReactNode
  label: string
  value: string
  note?: string
}) {
  return (
    <Card size="sm" className="gap-1.5">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardDescription>{label}</CardDescription>
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
      </CardHeader>
      <CardContent className="flex flex-col gap-0.5">
        <div className="text-lg font-semibold tracking-normal sm:text-xl">{value}</div>
        {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
      </CardContent>
    </Card>
  )
}
