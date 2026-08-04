import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { BadgeDollarSignIcon, GlobeIcon, ListChecksIcon, ReceiptTextIcon } from "lucide-react"

import { EmptyPanel, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Area } from "@/components/dither-kit/area"
import { AreaChart } from "@/components/dither-kit/area-chart"
import { Grid } from "@/components/dither-kit/grid"
import { Tooltip } from "@/components/dither-kit/tooltip"
import { XAxis } from "@/components/dither-kit/x-axis"
import { YAxis } from "@/components/dither-kit/y-axis"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api, type SummaryStats } from "@/lib/api"
import { formatNumber, formatSats } from "@/lib/format"

const chartMetrics = {
  sats: { label: "Sats routed", seriesLabel: "Sats", color: "orange", suffix: " sats" },
  paid: { label: "Invoices paid", seriesLabel: "Paid", color: "green", suffix: "" },
  created: { label: "Invoices created", seriesLabel: "Created", color: "blue", suffix: "" },
} as const

type ChartMetric = keyof typeof chartMetrics

export function DashboardPage() {
  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.summary(new Date().getTimezoneOffset()),
    refetchInterval: 10_000,
  })

  return (
    <>
      <PageHeader
        eyebrow="Live node surface"
        title="Dashboard"
        description="Track request volume, paid invoice flow, routed sats, and advertised domains without opening a terminal."
      />
      {summary.isLoading ? <LoadingRows rows={3} /> : null}
      {summary.isError ? <PageError message="Unable to load dashboard metrics." /> : null}
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
                <CardDescription>Created and paid invoices, plus routed sats, over the last 14 days.</CardDescription>
              </div>
              <Badge variant="secondary">{formatNumber(summary.data.invoices_total)} minted total</Badge>
            </CardHeader>
            <CardContent>
              {summary.data.invoice_activity.some((item) => item.sats > 0 || item.paid > 0 || item.created > 0) ? (
                <DashboardChart activity={summary.data.invoice_activity} />
              ) : (
                <EmptyPanel title="No invoice activity yet" description="Created and paid invoices will render here as wallets use generated invoices." />
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </>
  )
}

export function DashboardChart({ activity }: { activity: SummaryStats["invoice_activity"] }) {
  const [metric, setMetric] = useState<ChartMetric>("sats")
  const selected = chartMetrics[metric]
  const config = { [metric]: { label: selected.seriesLabel, color: selected.color } }

  return (
    <Tabs value={metric} onValueChange={(value) => setMetric(value as ChartMetric)}>
      <TabsList aria-label="Chart metric" className="grid h-auto w-full grid-cols-3">
        {Object.entries(chartMetrics).map(([key, item]) => (
          <TabsTrigger key={key} value={key} className="h-auto min-h-12 whitespace-normal py-1.5 text-xs sm:text-sm">
            {item.label}
          </TabsTrigger>
        ))}
      </TabsList>
      {(Object.keys(chartMetrics) as ChartMetric[]).map((panelMetric) => (
        <TabsContent
          key={panelMetric}
          value={panelMetric}
          forceMount
          className={panelMetric === metric ? "mt-0" : "hidden"}
        >
          {panelMetric === metric ? (
            <>
              <div className="h-[280px] w-full">
                <AreaChart
                  data={activity}
                  config={config}
                  margins={{ left: 48, right: 8, top: 12, bottom: 24 }}
                  bloom="aura"
                  ariaLabel={`${selected.label} over the last 14 days`}
                >
                  <Grid horizontal />
                  <XAxis dataKey="date" maxTicks={4} />
                  <YAxis />
                  <Tooltip
                    labelKey="date"
                    valueFormatter={(value) => `${formatNumber(value)}${selected.suffix}`}
                  />
                  <Area key={metric} dataKey={metric} variant="gradient" />
                </AreaChart>
              </div>
              <table className="sr-only">
                <caption>{selected.label} over the last 14 days</caption>
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    <th scope="col">{selected.label}</th>
                  </tr>
                </thead>
                <tbody>
                  {activity.map((item) => (
                    <tr key={item.date}>
                      <th scope="row">{item.date}</th>
                      <td>{`${formatNumber(item[metric])}${selected.suffix}`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : null}
        </TabsContent>
      ))}
    </Tabs>
  )
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
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3 pb-2">
        <CardDescription>{label}</CardDescription>
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        <div className="text-2xl font-semibold tracking-normal">{value}</div>
        {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
      </CardContent>
    </Card>
  )
}
