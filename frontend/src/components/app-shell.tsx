import { NavLink, Outlet, useLocation, useNavigate } from "react-router"
import { useQuery } from "@tanstack/react-query"
import {
  BadgeDollarSignIcon,
  CableIcon,
  ChevronRightIcon,
  CircleIcon,
  GaugeIcon,
  HelpCircleIcon,
  HomeIcon,
  IdCardIcon,
  InfoIcon,
  ListIcon,
  MenuIcon,
  NetworkIcon,
  PlugZapIcon,
  SettingsIcon,
  WebhookIcon,
  ZapIcon,
} from "lucide-react"
import { type ComponentProps, useEffect, useMemo } from "react"
import { toast } from "sonner"

import { CloudflareIcon } from "@/components/cloudflare-icon"
import { CodeBlock, CopyButton } from "@/components/common"
import { TailscaleIcon } from "@/components/tailscale-icon"
import { TemplateVariablesDialog } from "@/components/template-variables-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import { copyText } from "@/lib/format"
import { buildProxyHelpItems, type ProxyEngine, type ProxyHelpItem } from "@/lib/proxy-snippets"
import { cn } from "@/lib/utils"

const TIP_ADDRESS = "tips+ln@bigbones.net"

const navItems = [
  { to: "/", label: "Dashboard", icon: HomeIcon },
  { to: "/invoices/", label: "Invoices", icon: BadgeDollarSignIcon },
  { to: "/liquidity/", label: "Liquidity", icon: GaugeIcon },
  { to: "/logs/", label: "Request Logs", icon: ListIcon },
  { to: "/addresses/", label: "LN Addresses", icon: PlugZapIcon },
  { to: "/identities/", label: "Nostr Identities", icon: IdCardIcon },
  { to: "/settings/", label: "Settings", icon: SettingsIcon },
]

function SidebarNavLink({ onClick, ...props }: ComponentProps<typeof NavLink>) {
  const { isMobile, setOpenMobile } = useSidebar()

  return (
    <NavLink
      {...props}
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented && isMobile) {
          setOpenMobile(false)
        }
      }}
    />
  )
}

export function AppShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const health = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 10_000,
  })
  const version = useQuery({
    queryKey: ["version"],
    queryFn: api.version,
    staleTime: Number.POSITIVE_INFINITY,
  })
  const lndStatus = useQuery({
    queryKey: ["lnd-status"],
    queryFn: api.lndStatus,
    refetchInterval: 15_000,
  })
  const auth = useQuery({
    queryKey: ["auth-status"],
    queryFn: api.authStatus,
    refetchInterval: 10_000,
  })

  useEffect(() => {
    if (auth.data?.configured === false && !isSetupAllowedRoute(location.pathname)) {
      navigate("/settings/", { replace: true })
    }
  }, [auth.data?.configured, location.pathname, navigate])

  const serviceOk = health.data?.status === "ok"
  const lndConnected = lndStatus.data?.connected === true
  const configured = auth.data?.configured === true
  const versionLabel = `v${version.data?.version ?? "-"}`
  const lndValue = lndStatus.data ? (lndConnected ? "Connected" : "Offline") : "Checking"
  const lndTone = lndStatus.data ? (lndConnected ? "ok" : "error") : "pending"
  const tlsValue = tlsStatusLabel(lndStatus.data?.tls_status)
  const tlsTone = lndStatus.data ? tlsStatusTone(lndStatus.data.tls_status) : "pending"
  const macaroonValue = auth.data ? macaroonStatusLabel(auth.data) : "Checking"
  const macaroonTone = auth.data ? (configured ? "ok" : "error") : "pending"
  const proxyHelpItems = useMemo(() => buildProxyHelpItems(version.data?.dep_env), [version.data?.dep_env])

  return (
    <TooltipProvider>
      <SidebarProvider>
        <Sidebar collapsible="offcanvas">
          <SidebarHeader className="p-4">
            <SidebarNavLink to="/" className="flex items-center gap-3 rounded-md">
              <img src="/icon.svg" alt="" className="size-10 rounded-md" />
              <span className="flex min-w-0 flex-col">
                <span className="truncate text-sm font-semibold">lnSwitchboard</span>
                <span className="truncate text-xs text-muted-foreground">Lightning Address Router</span>
              </span>
            </SidebarNavLink>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup className="pt-0">
              <SidebarGroupContent>
                <SidebarMenu>
                  {navItems.map((item) => (
                    <SidebarMenuItem key={item.to}>
                      <SidebarMenuButton asChild isActive={isActiveRoute(location.pathname, item.to)} tooltip={item.label}>
                        <SidebarNavLink to={item.to}>
                          <item.icon />
                          <span>{item.label}</span>
                        </SidebarNavLink>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                  <SidebarMenuItem>
                    <Collapsible
                      defaultOpen={location.pathname.startsWith("/connections/")}
                      className="group/connections"
                    >
                      <CollapsibleTrigger asChild>
                        <SidebarMenuButton
                          type="button"
                          isActive={location.pathname.startsWith("/connections/")}
                          tooltip="Connections"
                        >
                          <CableIcon />
                          <span>Connections</span>
                          <ChevronRightIcon className="ml-auto transition-transform group-data-[state=open]/connections:rotate-90" />
                        </SidebarMenuButton>
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <SidebarMenuSub>
                          <SidebarMenuSubItem>
                            <SidebarMenuSubButton
                              asChild
                              isActive={isActiveRoute(location.pathname, "/connections/cloudflare/")}
                            >
                              <SidebarNavLink to="/connections/cloudflare/">
                                <CloudflareIcon />
                                <span>Cloudflare</span>
                              </SidebarNavLink>
                            </SidebarMenuSubButton>
                          </SidebarMenuSubItem>
                          <SidebarMenuSubItem>
                            <SidebarMenuSubButton
                              asChild
                              isActive={isActiveRoute(location.pathname, "/connections/tailscale/")}
                            >
                              <SidebarNavLink to="/connections/tailscale/">
                                <TailscaleIcon />
                                <span>Tailscale</span>
                              </SidebarNavLink>
                            </SidebarMenuSubButton>
                          </SidebarMenuSubItem>
                        </SidebarMenuSub>
                      </CollapsibleContent>
                    </Collapsible>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
            <SidebarGroup>
              <SidebarGroupLabel>Reference</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <Collapsible className="group/collapsible">
                      <CollapsibleTrigger asChild>
                        <SidebarMenuButton type="button" tooltip="Reverse Proxy Setup">
                          <HelpCircleIcon />
                          <span>Reverse Proxy Setup</span>
                          <ChevronRightIcon className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90" />
                        </SidebarMenuButton>
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <SidebarMenuSub>
                          {proxyHelpItems.map((item) => (
                            <SidebarMenuSubItem key={item.label}>
                              <ProxyHelpDialog item={item} />
                            </SidebarMenuSubItem>
                          ))}
                        </SidebarMenuSub>
                      </CollapsibleContent>
                    </Collapsible>
                  </SidebarMenuItem>
                  <SidebarMenuItem>
                    <TemplateVariablesDialog
                      trigger={(
                        <SidebarMenuButton asChild>
                          <button type="button">
                            <InfoIcon />
                            <span>Variables</span>
                          </button>
                        </SidebarMenuButton>
                      )}
                    />
                  </SidebarMenuItem>
                  <SidebarMenuItem>
                    <SidebarMenuButton asChild isActive={isActiveRoute(location.pathname, "/webhooks/")} tooltip="Webhooks">
                      <SidebarNavLink to="/webhooks/">
                        <WebhookIcon />
                        <span>Webhooks</span>
                      </SidebarNavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
          <SidebarFooter className="gap-2 p-2">
            <div className="flex flex-col gap-2 rounded-md border bg-background/70 p-2 text-xs">
              <StatusRow label="API" tone={serviceOk ? "ok" : "pending"} value={serviceOk ? "Online" : "Checking"} />
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <StatusRow
                      label="LND"
                      tone={lndTone}
                      value={lndValue}
                    />
                  </div>
                </TooltipTrigger>
                <TooltipContent side="right">
                  <span>{lndStatus.data?.message ?? "Checking LND connection"}</span>
                </TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div>
                    <StatusRow
                      label="TLS"
                      tone={tlsTone}
                      value={tlsValue}
                    />
                  </div>
                </TooltipTrigger>
                <TooltipContent side="right">
                  <span>{tlsStatusMessage(lndStatus.data)}</span>
                </TooltipContent>
              </Tooltip>
              <StatusRow
                label="Macaroon"
                tone={macaroonTone}
                value={macaroonValue}
              />
            </div>
            <ProductFooter versionLabel={versionLabel} compact />
          </SidebarFooter>
        </Sidebar>
        <SidebarInset>
          <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b bg-background/95 px-4 backdrop-blur md:hidden">
            <div className="flex items-center gap-2">
              <SidebarTrigger aria-label="Open navigation">
                <MenuIcon />
              </SidebarTrigger>
              <img src="/icon.svg" alt="" className="size-7 rounded-md" />
              <span className="font-semibold">lnSwitchboard</span>
            </div>
            <Button asChild variant="ghost" size="sm">
              <NavLink to="/settings/">Settings</NavLink>
            </Button>
          </header>
          <main className="mx-auto flex w-full max-w-7xl flex-none flex-col gap-6 px-4 py-5 md:px-8 md:py-8">
            <Outlet />
          </main>
          <footer className="mx-auto flex w-full max-w-7xl px-4 pb-6 md:hidden">
            <ProductFooter versionLabel={versionLabel} />
          </footer>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}

function ProxyHelpDialog({
  item,
}: {
  item: ProxyHelpItem
}) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <SidebarMenuSubButton asChild>
          <button type="button">
            <ProxyEngineIcon engine={item.icon} />
            <span>{item.label}</span>
          </button>
        </SidebarMenuSubButton>
      </DialogTrigger>
      <DialogContent className="min-w-0 max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{item.title}</DialogTitle>
          <DialogDescription>{item.description}</DialogDescription>
        </DialogHeader>
        <section className="flex min-w-0 flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-medium">Snippet</h3>
            <CopyButton value={item.snippet} label="Copy" copiedLabel={`${item.title} copied`} />
          </div>
          <CodeBlock>{item.snippet}</CodeBlock>
        </section>
      </DialogContent>
    </Dialog>
  )
}

function ProxyEngineIcon({ engine }: { engine: ProxyEngine }) {
  if (engine === "nginx") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path fill="#009639" d="M12 1.8 3.5 6.7v9.8l8.5 4.9 8.5-4.9V6.7L12 1.8Z" />
        <path fill="#ffffff" d="M7.7 16.5v-9h2.1l4.3 5.2V7.5h2.2v9h-2l-4.4-5.3v5.3H7.7Z" />
      </svg>
    )
  }

  if (engine === "caddy") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="9.5" fill="#1f8fff" />
        <path fill="#ffffff" d="M16.8 15.1a5.6 5.6 0 1 1 0-6.2l-1.9 1.1a3.4 3.4 0 1 0 0 4l1.9 1.1Z" />
        <path fill="#9bf2ff" d="M14.4 6.8c2.1.7 3.6 2.8 3.6 5.2s-1.5 4.5-3.6 5.2l-.8-1.7a3.7 3.7 0 0 0 0-7l.8-1.7Z" opacity="0.9" />
      </svg>
    )
  }

  return <NetworkIcon />
}

function StatusRow({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone: "ok" | "pending" | "error"
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("flex items-center gap-1 font-medium", tone === "error" ? "text-destructive" : "text-foreground")}>
        <CircleIcon className={cn("size-2 fill-current", statusToneClass(tone))} />
        {value}
      </span>
    </div>
  )
}

function statusToneClass(tone: "ok" | "pending" | "error") {
  if (tone === "ok") return "text-primary"
  if (tone === "error") return "text-destructive"
  return "text-muted-foreground"
}

function macaroonStatusLabel(status?: { configured: boolean; source?: string }) {
  if (!status?.configured) return "Needed"
  return status.source === "file" ? "Mounted" : "Manual"
}

function tlsStatusLabel(status?: string | null) {
  if (status === "valid") return "Valid"
  if (status === "expired") return "Expired"
  if (status === "not_yet_valid") return "Not active"
  if (status === "missing") return "Missing"
  if (status === "invalid") return "Invalid"
  if (status === "unknown") return "Unknown"
  return "Checking"
}

function tlsStatusTone(status?: string | null): "ok" | "pending" | "error" {
  if (status === "valid") return "ok"
  if (!status || status === "unknown") return "pending"
  return "error"
}

function tlsStatusMessage(status?: {
  tls_message?: string | null
  tls_expires_at?: string | null
}) {
  if (!status) return "Checking LND TLS certificate"
  if (status.tls_message) return status.tls_message
  if (status.tls_expires_at) return `TLS certificate expires at ${status.tls_expires_at}`
  return status.tls_message ?? "TLS certificate status unavailable"
}

function ProductFooter({
  versionLabel,
  compact = false,
  className,
}: {
  versionLabel: string
  compact?: boolean
  className?: string
}) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5 text-xs text-muted-foreground", className)}>
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium text-foreground">lnSwitchboard</span>
        <Badge variant="outline" className="h-5 px-1.5 font-mono text-[10px] font-normal text-muted-foreground">
          {versionLabel}
        </Badge>
        <span className="text-[11px]">
          &copy; 2026{" "}
          <a
            href="https://github.com/RyleaStark/lnSwitchboard"
            target="_blank"
            rel="noreferrer"
            className="underline-offset-2 hover:text-foreground hover:underline"
          >
            Rylea Stark
          </a>
        </span>
      </div>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className={cn(
              "h-6 w-fit gap-1.5 px-0 text-xs font-normal text-muted-foreground hover:bg-transparent hover:text-foreground",
              compact && "text-[11px]",
            )}
            onClick={async () => {
              await copyText(TIP_ADDRESS)
              toast.success("Tip address copied")
            }}
          >
            <ZapIcon data-icon="inline-start" className="size-3.5" />
            <span className="font-mono">{TIP_ADDRESS}</span>
          </Button>
        </TooltipTrigger>
        <TooltipContent side={compact ? "right" : "top"}>
          <span>Copy tip address</span>
        </TooltipContent>
      </Tooltip>
    </div>
  )
}

function isActiveRoute(pathname: string, target: string) {
  if (target === "/") return pathname === "/"
  return pathname.startsWith(target)
}

function isSetupAllowedRoute(pathname: string) {
  return pathname.startsWith("/settings") || pathname.startsWith("/webhooks")
}
