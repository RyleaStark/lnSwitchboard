import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { CheckCircle2Icon, ClockIcon, ForwardIcon, GlobeLockIcon, RouteIcon, ShieldCheckIcon, WebhookIcon } from "lucide-react"

import { CodeBlock, CopyButton, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api, type EnvSetting } from "@/lib/api"

const fieldRows = [
  ["event", "Always payment.settled so receivers can filter future webhook types."],
  ["source", "Always lnswitchboard; useful when one receiver aggregates events from multiple apps."],
  ["version", "lnSwitchboard version that fired the webhook."],
  ["address_id", "Internal UUID of the LN address override. Useful if the receiver later calls the API."],
  ["ln_address", "Full handle that got paid, including any +tag."],
  ["local_part", "Base handle before the domain and before any +tag."],
  ["username", "What the payer typed before the domain. This may include a +tag."],
  ["tag", "The part after + when tags are used. Null when the payment did not include one."],
  ["domain", "Host reached by the payer after proxy headers are resolved."],
  ["amount_msat", "Payment size in millisats, using the exact invoice amount."],
  ["amount_sat", "Same amount rounded down to sats for quick math."],
  ["payment_hash", "32-byte hex hash that uniquely identifies the invoice."],
  ["payment_request", "BOLT11 invoice string for reconciliation with other systems."],
  ["settled_at", "ISO-8601 UTC timestamp for when lnSwitchboard marked the invoice settled."],
  ["forwarded", "True when the payment came through a forwarded LN address. Omitted for older/local-only events."],
  ["forward_to", "Target Lightning Address for forwarded payments, such as user@wallet.example."],
  ["settlement_source", "remote_verify for forwarded invoices that were confirmed by the target provider's verify URL."],
  ["comment", "Payer note from LUD-12, or null when the payer did not provide one."],
  ["payer_data", "Parsed JSON object from LUD-18 when payer data is allowed or required."],
  ["payer_data_raw", "Original payer data string, useful when the receiver needs the untouched payload."],
  ["verify_url", "Direct lnSwitchboard verify endpoint for checking the invoice state against LND."],
  ["invoice_event_id", "Row ID in the invoice_events table, also visible through /api/invoices."],
  ["request_log_id", "Matching request log row ID used by /api/logs/recent."],
] as const

const headerRows = [
  ["User-Agent", "lnSwitchboard/<version>; lets receivers identify this app without parsing JSON."],
  ["X-LnSwitchboard-Event", "Mirrors the event field for routing traffic at a gateway."],
  ["X-LnSwitchboard-Version", "Mirrors version for edge filtering and audit logs."],
  ["X-LnSwitchboard-Address-Id", "Repeats the address UUID so receivers can route before reading the body."],
] as const

const tips = [
  "Accept application/json POST requests.",
  "Respond within a couple seconds so the delivery is treated as successful.",
  "Use verify_url when a receiver needs a second settlement check.",
  "Keep the endpoint on HTTPS, use an unguessable path, or reject requests missing the lnSwitchboard headers.",
] as const

const forwardedCaveats = [
  "Paid webhooks for forwarded invoices only fire when the target provider returns a usable verify URL.",
  "If the target omits verify, the request log still shows a forward event, but no payment.settled webhook is dispatched.",
  "Forwarded invoice status is shown as Forwarded in the invoice ledger even after remote settlement is confirmed.",
  "Wallet-facing LNURL metadata is preserved from the target provider so spec-compliant wallets do not reject the invoice.",
] as const

export function WebhooksPage() {
  const version = useQuery({
    queryKey: ["version"],
    queryFn: api.version,
    staleTime: Number.POSITIVE_INFINITY,
  })
  const env = useQuery({
    queryKey: ["env-settings"],
    queryFn: api.envSettings,
  })
  const retrySummary = useMemo(() => retrySummaryFromSettings(env.data?.settings), [env.data?.settings])

  if (version.isLoading) {
    return (
      <>
        <PageHeader
          eyebrow="Reference"
          title="Webhooks"
          description="Delivery contract for settled Lightning payment automation."
        />
        <LoadingRows rows={4} />
      </>
    )
  }

  if (version.isError || !version.data?.version) {
    return (
      <>
        <PageHeader
          eyebrow="Reference"
          title="Webhooks"
          description="Delivery contract for settled Lightning payment automation."
        />
        <PageError message="Unable to load the app version for webhook examples." />
      </>
    )
  }

  const appVersion = version.data.version
  const headerExample = buildHeaderExample(appVersion)
  const payloadExample = buildPayloadExample(appVersion)
  const forwardedPayloadExample = buildForwardedPayloadExample(appVersion)
  const nginxExample = buildNginxExample(appVersion)
  const caddyExample = buildCaddyExample(appVersion)

  return (
    <>
      <PageHeader
        eyebrow="Reference"
        title="Webhooks"
        description="Use settled-payment webhooks to notify n8n, databases, bots, and other downstream services when a routed Lightning invoice is paid."
        action={<Badge variant="outline" className="font-mono">v{appVersion}</Badge>}
      />

      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><WebhookIcon /> Payment settled event</CardTitle>
            <CardDescription>
              A webhook is a doorbell for another app. Every configured URL receives the same JSON package when a matching invoice settles.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <StepCard icon={<RouteIcon />} title="Wallet pays" description="The payer requests local_part@domain. Tags such as local_part+vip are included." />
            <StepCard icon={<ClockIcon />} title="Webhook posts" description={`Each configured URL receives a POST. Failures use ${retrySummary}.`} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><GlobeLockIcon /> Receiver checklist</CardTitle>
            <CardDescription>Keep receivers small, fast, and easy to filter at the edge.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="grid gap-5 text-sm text-muted-foreground">
              {tips.map((tip) => (
                <li key={tip} className="flex items-start gap-3">
                  <CheckCircle2Icon className="mt-0.5 shrink-0 text-primary" />
                  <span>{tip}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Example request</CardTitle>
          <CardDescription>Headers and body sent to each webhook URL attached to the paid LN address.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-5">
          <DocCode title="Headers" value={headerExample} />
          <DocCode title="Payload" value={payloadExample} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ForwardIcon /> Forwarded invoices</CardTitle>
          <CardDescription>Forwarded LN addresses use the target provider's invoice and can only prove settlement when that provider exposes a verify endpoint.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-5">
          <div className="grid gap-3 lg:grid-cols-3">
            <StepCard icon={<ShieldCheckIcon />} title="Remote verify required" description="lnSwitchboard polls the target verify URL instead of local LND. Without verify, paid webhook automation is unavailable for that forwarded invoice." />
            <StepCard icon={<WebhookIcon />} title="Same event type" description="Successful forwarded settlements still post payment.settled, with forwarded, forward_to, and settlement_source fields added to the payload." />
            <StepCard icon={<RouteIcon />} title="Metadata stays intact" description="The target wallet text is preserved because LNURL invoices bind the BOLT11 invoice to the discovery metadata hash." />
          </div>
          <div className="overflow-hidden rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Caveat</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {forwardedCaveats.map((caveat) => (
                  <TableRow key={caveat}>
                    <TableCell className="whitespace-normal leading-6 text-muted-foreground">{caveat}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DocCode title="Forwarded payload differences" value={forwardedPayloadExample} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Payload fields</CardTitle>
          <CardDescription>All fields are JSON strings, numbers, objects, or null values.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-hidden rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Meaning</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {fieldRows.map(([field, meaning]) => (
                  <TableRow key={field}>
                    <TableCell className="font-mono">{field}</TableCell>
                    <TableCell className="whitespace-normal leading-6 text-muted-foreground">{meaning}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Headers</CardTitle>
          <CardDescription>Use these headers to route or reject requests before parsing the JSON body.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-hidden rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Header</TableHead>
                  <TableHead>Why it exists</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {headerRows.map(([header, meaning]) => (
                  <TableRow key={header}>
                    <TableCell className="font-mono">{header}</TableCell>
                    <TableCell className="whitespace-normal leading-6 text-muted-foreground">{meaning}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Receiver guard examples</CardTitle>
          <CardDescription>Example reverse-proxy guards for webhook endpoints that reject wrong methods, missing headers, and old clients.</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="nginx" className="flex flex-col gap-4">
            <TabsList variant="line" className="h-10 w-fit justify-start gap-2 p-0">
              <TabsTrigger
                value="nginx"
                className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent"
              >
                NGINX
              </TabsTrigger>
              <TabsTrigger
                value="caddy"
                className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent"
              >
                Caddy
              </TabsTrigger>
            </TabsList>
            <TabsContent value="nginx">
              <DocCode title="nginx.conf" value={nginxExample} />
            </TabsContent>
            <TabsContent value="caddy">
              <DocCode title="Caddyfile" value={caddyExample} />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </>
  )
}

function StepCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode
  title: string
  description: string
}) {
  return (
    <div className="flex items-start gap-3 rounded-md border bg-muted/20 p-3">
      <span className="mt-0.5 shrink-0 text-primary">{icon}</span>
      <div className="flex min-w-0 flex-col gap-1">
        <div className="font-medium">{title}</div>
        <p className="text-sm leading-6 text-muted-foreground">{description}</p>
      </div>
    </div>
  )
}

function DocCode({ title, value }: { title: string; value: string }) {
  return (
    <section className="flex min-w-0 flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-medium">{title}</h2>
        <CopyButton value={value} label="Copy" copiedLabel={`${title} copied`} />
      </div>
      <CodeBlock className="max-h-[32rem]">{value}</CodeBlock>
    </section>
  )
}

function retrySummaryFromSettings(settings?: EnvSetting[]): string {
  const retries = numberSetting(settings, "WEBHOOK_MAX_RETRIES", 5)
  const windowSeconds = numberSetting(settings, "WEBHOOK_RETRY_WINDOW_SECONDS", 600)
  if (retries <= 0) return "no automatic retries"
  return `${retries} ${retries === 1 ? "retry" : "retries"} over ${formatDuration(windowSeconds)}`
}

function numberSetting(settings: EnvSetting[] | undefined, key: string, fallback: number): number {
  const value = settings?.find((item) => item.key === key)?.value
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function formatDuration(seconds: number): string {
  if (seconds <= 0) return "0 seconds"
  if (seconds % 60 === 0) {
    const minutes = seconds / 60
    return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`
  }
  return `${seconds} ${seconds === 1 ? "second" : "seconds"}`
}

function buildHeaderExample(version: string): string {
  return `POST https://hooks.example.com/payments
User-Agent: lnSwitchboard/${version}
Content-Type: application/json
X-LnSwitchboard-Event: payment.settled
X-LnSwitchboard-Version: ${version}
X-LnSwitchboard-Address-Id: 6b28d3c6-2cf5-4c87-97d6-0a9d38b2df2c`
}

function buildPayloadExample(version: string): string {
  return JSON.stringify(
    {
      event: "payment.settled",
      source: "lnswitchboard",
      version,
      address_id: "6b28d3c6-2cf5-4c87-97d6-0a9d38b2df2c",
      ln_address: "pay+alice@testserver",
      local_part: "pay",
      username: "pay+alice",
      tag: "alice",
      domain: "testserver",
      amount_msat: 42000,
      amount_sat: 42,
      payment_hash: "4c51...e9af",
      payment_request: "lnbc42000n1psample",
      settled_at: "2024-05-01T12:34:56.789012+00:00",
      comment: "pizza time",
      payer_data: {
        name: "Alice",
      },
      payer_data_raw: "{\"name\":\"Alice\"}",
      verify_url: "https://testserver/.well-known/lnurlp/pay/verify/4c51...e9af",
      invoice_event_id: 137,
      request_log_id: 912,
    },
    null,
    2,
  )
}

function buildForwardedPayloadExample(version: string): string {
  return JSON.stringify(
    {
      event: "payment.settled",
      source: "lnswitchboard",
      version,
      address_id: "6b28d3c6-2cf5-4c87-97d6-0a9d38b2df2c",
      ln_address: "tips@testserver",
      local_part: "tips",
      username: "tips",
      tag: null,
      domain: "testserver",
      amount_msat: 21000,
      amount_sat: 21,
      payment_hash: "8d21...b47a",
      payment_request: "lnbc21000n1pforwarded",
      settled_at: "2024-05-01T12:34:56.789012+00:00",
      verify_url: "https://target.example/lnurl/verify/8d21...b47a",
      forwarded: true,
      forward_to: "bones@walletofsatoshi.com",
      settlement_source: "remote_verify",
      invoice_event_id: 138,
      request_log_id: 913,
    },
    null,
    2,
  )
}

function buildNginxExample(version: string): string {
  return `location = /events/lnswitchboard/settle {
  if ($request_method != POST) { return 405; }
  if ($http_x_lnswitchboard_address_id = "") { return 400; }
  if ($http_x_lnswitchboard_version = "") { return 400; }
  if ($http_x_lnswitchboard_event != "payment.settled") { return 403; }
  if ($http_user_agent !~ "^lnSwitchboard/") { return 403; }
  if ($http_x_lnswitchboard_version < "${version}") { return 426; }

  # Proxy to your receiver
  proxy_pass http://127.0.0.1:222;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}`
}

function buildCaddyExample(version: string): string {
  return `@lnSwitchboardWebhook {
  method POST
  header X-LnSwitchboard-Address-Id *
  header X-LnSwitchboard-Version ${version}
  header X-LnSwitchboard-Event payment.settled
  header_regexp UserAgent User-Agent ^lnSwitchboard/
}

route /events/lnswitchboard/settle {
  reverse_proxy @lnSwitchboardWebhook 127.0.0.1:222
  respond "invalid lnSwitchboard webhook request" 403
}`
}
