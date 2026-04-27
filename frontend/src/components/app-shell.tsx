import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import {
  BadgeDollarSignIcon,
  CircleIcon,
  GaugeIcon,
  HeartIcon,
  HelpCircleIcon,
  HomeIcon,
  IdCardIcon,
  ListIcon,
  MenuIcon,
  PlugZapIcon,
  SettingsIcon,
} from "lucide-react"
import { useEffect } from "react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import { copyText } from "@/lib/format"
import { cn } from "@/lib/utils"

const TIP_ADDRESS = "lnswitchboard+tips@bigbones.net"

const navItems = [
  { to: "/", label: "Dashboard", icon: HomeIcon },
  { to: "/invoices/", label: "Invoices", icon: BadgeDollarSignIcon },
  { to: "/liquidity/", label: "Liquidity", icon: GaugeIcon },
  { to: "/logs/", label: "Request Logs", icon: ListIcon },
  { to: "/addresses/", label: "LN Addresses", icon: PlugZapIcon },
  { to: "/identities/", label: "Nostr Identities", icon: IdCardIcon },
  { to: "/settings/", label: "Settings", icon: SettingsIcon },
]

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
    if (auth.data?.configured === false && !location.pathname.startsWith("/settings")) {
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

  return (
    <TooltipProvider>
      <SidebarProvider>
        <Sidebar collapsible="offcanvas">
          <SidebarHeader className="p-4">
            <NavLink to="/" className="flex items-center gap-3 rounded-md">
              <img src="/icon.svg" alt="" className="size-10 rounded-md" />
              <span className="flex min-w-0 flex-col">
                <span className="truncate text-sm font-semibold">lnSwitchboard</span>
                <span className="truncate text-xs text-muted-foreground">Lightning Address Router</span>
              </span>
            </NavLink>
          </SidebarHeader>
          <SidebarContent>
            <SidebarGroup className="pt-0">
              <SidebarGroupContent>
                <SidebarMenu>
                  {navItems.map((item) => (
                    <SidebarMenuItem key={item.to}>
                      <SidebarMenuButton asChild isActive={isActiveRoute(location.pathname, item.to)} tooltip={item.label}>
                        <NavLink to={item.to}>
                          <item.icon />
                          <span>{item.label}</span>
                        </NavLink>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
            <SidebarGroup>
              <SidebarGroupLabel>Reference</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <SidebarMenuButton asChild tooltip="Project wiki">
                      <a href="https://github.com/RyleaStark/lnSwitchboard/wiki" target="_blank" rel="noreferrer">
                        <HelpCircleIcon />
                        <span>Help</span>
                      </a>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
          <SidebarFooter className="gap-3 p-4">
            <div className="flex flex-col gap-2 rounded-md border bg-background/70 p-3 text-xs">
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
          <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6 px-4 py-5 md:px-8 md:py-8">
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
    <div className={cn("flex min-w-0 flex-col gap-2 rounded-md border bg-background/50 p-3 text-xs", className)}>
      <div className="flex min-w-0 items-center justify-between gap-2">
        <span className="truncate font-medium text-foreground">lnSwitchboard</span>
        <Badge variant="outline" className="font-mono text-[10px]">
          {versionLabel}
        </Badge>
      </div>
      <div className="text-[11px] leading-4 text-muted-foreground">&copy; 2026 Rylea Stark</div>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant={compact ? "ghost" : "outline"}
            size="sm"
            className={cn(
              "min-w-0 justify-start text-xs",
              compact
                ? "mt-1 h-8 w-full gap-1.5 px-2 text-muted-foreground"
                : "h-8 w-full",
            )}
            onClick={async () => {
              await copyText(TIP_ADDRESS)
              toast.success("Tip address copied")
            }}
          >
            <HeartIcon data-icon="inline-start" />
            <span>{compact ? "Copy tip address" : "Tip sats"}</span>
            {compact ? null : <span className="min-w-0 truncate font-mono">{TIP_ADDRESS}</span>}
          </Button>
        </TooltipTrigger>
        <TooltipContent side={compact ? "right" : "top"}>
          <span className="font-mono">{TIP_ADDRESS}</span>
        </TooltipContent>
      </Tooltip>
    </div>
  )
}

function isActiveRoute(pathname: string, target: string) {
  if (target === "/") return pathname === "/"
  return pathname.startsWith(target)
}
