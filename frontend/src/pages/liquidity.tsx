import { useQuery } from "@tanstack/react-query"
import { ExternalLinkIcon, HelpCircleIcon } from "lucide-react"

import { EmptyPanel, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api, type Channel } from "@/lib/api"
import { channelPeer, channelPeerIdentifier, formatSats, receivableCapacity, reserveTotal, sendableCapacity } from "@/lib/format"

export function LiquidityPage() {
  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: api.channels,
    refetchInterval: 10_000,
  })
  const rows = [...(channels.data?.channels ?? [])].sort((a, b) => receivableCapacity(b) - receivableCapacity(a))
  const maxChannel = rows[0]

  return (
    <>
      <PageHeader
        title="Liquidity"
      />
      {channels.isLoading ? <LoadingRows rows={3} /> : null}
      {channels.isError ? <PageError message="Unable to load channel liquidity." onRetry={() => void channels.refetch()} retrying={channels.isFetching} /> : null}
      {channels.data ? (
        <div className="flex flex-col gap-5">
          <div className="grid gap-3 lg:grid-cols-[1.2fr_0.8fr]">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  Biggest one-shot invoice
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <HelpCircleIcon className="size-4 text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent>
                      Wallets need one invoice routed through one channel, so lnSwitchboard uses the biggest receivable channel.
                    </TooltipContent>
                  </Tooltip>
                </CardTitle>
                <CardDescription>Maximum amount a wallet can request right now.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-2">
                <div className="text-3xl font-semibold">{formatSats(maxChannel ? receivableCapacity(maxChannel) : 0)}</div>
                <p className="text-sm text-muted-foreground">{maxChannel ? `via ${channelPeer(maxChannel)}` : "Add a channel to receive sats."}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Total inbound</CardTitle>
                <CardDescription>Sum of advertised receivable capacity across channels.</CardDescription>
              </CardHeader>
              <CardContent className="text-3xl font-semibold">{formatSats(channels.data.total_receiving_capacity_sat)}</CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Inbound capacity by peer</CardTitle>
              <CardDescription>Sorted by receivable capacity descending.</CardDescription>
            </CardHeader>
            <CardContent>
              {rows.length === 0 ? (
                <EmptyPanel title="No channels found" description="Open a channel to advertise LNURL receiving capacity." />
              ) : (
                <>
                  <div className="hidden overflow-hidden rounded-md border lg:block">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Peer</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Capacity</TableHead>
                          <TableHead>Sendable</TableHead>
                          <TableHead>Receivable</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {rows.map((channel, index) => (
                          <TableRow key={String(channel.channel_id || channel.chan_id || channel.channel_point || index)}>
                            <TableCell><Peer channel={channel} /></TableCell>
                            <TableCell><Status active={channel.active} /></TableCell>
                            <TableCell>
                              <div className="flex flex-col gap-1">
                                <span>{formatSats(channel.capacity_sat || 0)}</span>
                                {reserveTotal(channel) > 0 ? <span className="text-xs text-muted-foreground">{formatSats(reserveTotal(channel))} reserved</span> : null}
                              </div>
                            </TableCell>
                            <TableCell>{formatSats(sendableCapacity(channel))}</TableCell>
                            <TableCell>{formatSats(receivableCapacity(channel))}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  <div className="grid gap-3 lg:hidden">
                    {rows.map((channel, index) => (
                      <Card key={String(channel.channel_id || channel.chan_id || channel.channel_point || index)}>
                        <CardHeader>
                          <CardTitle className="text-base"><Peer channel={channel} /></CardTitle>
                          <CardDescription><Status active={channel.active} /></CardDescription>
                        </CardHeader>
                        <CardContent className="grid grid-cols-2 gap-3 text-sm">
                          <Metric label="Capacity" value={formatSats(channel.capacity_sat || 0)} />
                          <Metric label="Receivable" value={formatSats(receivableCapacity(channel))} />
                          <Metric label="Sendable" value={formatSats(sendableCapacity(channel))} />
                          <Metric label="Reserved" value={formatSats(reserveTotal(channel))} />
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </>
  )
}

function Peer({ channel }: { channel: Channel }) {
  const label = channelPeer(channel)
  const identifier = channelPeerIdentifier(channel, { compact: true })
  const showIdentifier = Boolean(identifier && identifier !== label)
  const content = (
    <>
      <span className="inline-flex min-w-0 items-center gap-1">
        <span className="truncate">{label}</span>
        {channel.remote_pubkey ? <ExternalLinkIcon /> : null}
      </span>
      {showIdentifier ? <code className="truncate font-mono text-xs text-muted-foreground">{identifier}</code> : null}
    </>
  )

  if (channel.remote_pubkey) {
    return (
      <a className="flex min-w-0 max-w-fit flex-col gap-1 font-medium underline-offset-4 hover:underline" href={`https://amboss.space/node/${encodeURIComponent(channel.remote_pubkey)}`} target="_blank" rel="noreferrer">
        {content}
      </a>
    )
  }
  return <span className="flex min-w-0 flex-col gap-1 font-medium">{content}</span>
}

function Status({ active }: { active?: boolean }) {
  return <Badge variant={active ? "default" : "secondary"}>{active ? "Active" : "Inactive"}</Badge>
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="text-xs font-medium uppercase tracking-normal text-muted-foreground">{label}</div>
      <div className="mt-1 font-medium">{value}</div>
    </div>
  )
}
