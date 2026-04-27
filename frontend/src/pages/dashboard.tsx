import { useQuery } from "@tanstack/react-query"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"
import { BadgeDollarSignIcon, GlobeIcon, ListChecksIcon, ReceiptTextIcon } from "lucide-react"

import { EmptyPanel, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { api } from "@/lib/api"
import { formatNumber, formatSats } from "@/lib/format"

const chartConfig = {
  sats: { label: "Sats", color: "var(--chart-1)" },
  paid: { label: "Paid", color: "var(--chart-2)" },
} satisfies ChartConfig

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
                <CardTitle>Sats stacked</CardTitle>
                <CardDescription>Settled invoice activity over the last 14 days.</CardDescription>
              </div>
              <Badge variant="secondary">{formatNumber(summary.data.invoices_total)} minted total</Badge>
            </CardHeader>
            <CardContent>
              {summary.data.invoice_activity.some((item) => item.sats > 0 || item.paid > 0) ? (
                <ChartContainer config={chartConfig} className="h-[280px] w-full">
                  <AreaChart data={summary.data.invoice_activity} margin={{ left: 8, right: 8, top: 12, bottom: 0 }}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} minTickGap={16} />
                    <YAxis tickLine={false} axisLine={false} tickMargin={8} width={52} />
                    <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
                    <Area dataKey="sats" type="monotone" stroke="var(--color-sats)" fill="var(--color-sats)" fillOpacity={0.2} />
                  </AreaChart>
                </ChartContainer>
              ) : (
                <EmptyPanel title="No paid activity yet" description="Settled invoices will render here once wallets start paying generated invoices." />
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </>
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
