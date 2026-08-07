import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ExternalLinkIcon, NetworkIcon, RefreshCwIcon, ShieldCheckIcon, Trash2Icon, XIcon } from "lucide-react"
import QRCode from "qrcode"
import { useLocation } from "react-router"

import { toast } from "sonner"

import { CloudflareIcon } from "@/components/cloudflare-icon"
import { CopyButton } from "@/components/common"
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
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,

  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, api, type CloudflareAuthorization, type ProviderConnection, type TailscaleLogin } from "@/lib/api"

export function ConnectionsPage() {
  const location = useLocation()
  return location.pathname.includes("/connections/tailscale") ? (
    <TailscaleConnectionsPage />
  ) : (
    <CloudflareConnectionsPage />
  )
}

function CloudflareConnectionsPage() {
  const queryClient = useQueryClient()

  const [accountId, setAccountId] = useState("")
  const [zoneId, setZoneId] = useState("")
  const [hostname, setHostname] = useState("")
  const [apiToken, setApiToken] = useState("")
  const [authorizing, setAuthorizing] = useState(false)

  const connections = useQuery({ queryKey: ["connections"], queryFn: api.connections })
  const setup = useQuery({ queryKey: ["cloudflare-setup"], queryFn: api.cloudflareSetup })
  const cloudflareConnection = connections.data?.connections.find(
    (connection) => connection.provider === "cloudflare",
  )
  const provider = connections.data?.providers.find((item) => item.id === "cloudflare")
  const available = setup.data?.available === true && provider?.capability === "available"
  const pendingAuthorization = useQuery({
    queryKey: ["cloudflare-authorization"],
    queryFn: api.cloudflareAuthorization,
    enabled: available && !cloudflareConnection,
    retry: false,
  })
  const authorization = pendingAuthorization.data ?? null
  const authorizationMissing =
    pendingAuthorization.error instanceof ApiError && pendingAuthorization.error.status === 404

  const selectedAccount = useMemo(
    () => authorization?.accounts.find((account) => account.id === accountId),
    [accountId, authorization],
  )

  useEffect(() => {
    if (!authorization) return
    const account = authorization.accounts[0]
    setAccountId(account?.id ?? "")
    setZoneId(account?.zones[0]?.id ?? "")
  }, [authorization])

  useEffect(() => {
    if (!selectedAccount?.zones.some((zone) => zone.id === zoneId)) {
      setZoneId(selectedAccount?.zones[0]?.id ?? "")
    }
  }, [selectedAccount, zoneId])

  const authorize = async () => {
    const token = apiToken.trim()
    if (!token || authorizing) return
    setAuthorizing(true)
    try {
      const result = await api.authorizeCloudflare(token)
      queryClient.setQueryData(["cloudflare-authorization"], result)
      toast.success("Cloudflare token validated")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Token validation failed")
    } finally {
      setApiToken("")
      setAuthorizing(false)
    }
  }

  const provision = useMutation({
    mutationFn: api.provisionCloudflare,
    onSuccess: async () => {
      setHostname("")
      queryClient.removeQueries({ queryKey: ["cloudflare-authorization"] })
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Cloudflare Tunnel is provisioning")
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Tunnel provisioning failed"),
  })

  const cancelAuthorization = useMutation({
    mutationFn: api.cancelCloudflareAuthorization,
    onSuccess: () =>
      queryClient.removeQueries({ queryKey: ["cloudflare-authorization"] }),
    onError: (error) =>
      toast.error(
        error instanceof Error ? error.message : "Unable to cancel authorization",
      ),
  })

  const refreshStatus = useMutation({
    mutationFn: api.refreshCloudflareStatus,
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["connections"] }),
    onError: (error) => toast.error(error instanceof Error ? error.message : "Status refresh failed"),
  })

  const disconnect = useMutation({
    mutationFn: api.disconnectCloudflare,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Cloudflare Tunnel disconnected")
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Disconnect failed"),
  })

  if (
    connections.isPending ||
    setup.isPending ||
    (pendingAuthorization.isEnabled && pendingAuthorization.isPending)
  ) {
    return <ConnectionsSkeleton />
  }

  if (
    connections.isError ||
    setup.isError ||
    (pendingAuthorization.isError && !authorizationMissing)
  ) {
    return <ConnectionsLoadError />
  }

  const onboardingDisabled = !available && !cloudflareConnection

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start gap-3">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-[#f38020]/10 ring-1 ring-[#f38020]/20">
          <CloudflareIcon className="size-7" />
        </div>
        <div className="min-w-0">
          <h1 className="font-heading text-2xl font-semibold tracking-tight text-balance">Connections</h1>
          <p className="mt-1 max-w-2xl text-sm leading-normal text-pretty text-muted-foreground">
            Connect managed edge services to lnSwitchboard&apos;s isolated public listener. Administration stays on your private network.
          </p>
        </div>
      </header>

      <Card
        aria-disabled={onboardingDisabled || undefined}
        className={onboardingDisabled ? "opacity-75" : undefined}
      >
        <CardHeader>
          <div className="flex items-center gap-2">
            <CloudflareIcon className="size-5" />
            <CardTitle><h2>Cloudflare Tunnel</h2></CardTitle>
          </div>
          <CardDescription className="max-w-2xl text-pretty">
            Creates a remotely managed tunnel and proxied DNS record for one public hostname. Tunnel traffic reaches only port 21212.
          </CardDescription>
          <CardAction>
            {cloudflareConnection ? (
              <ConnectionStatusBadge status={cloudflareConnection.status} />
            ) : available ? (
              <Badge variant="outline">Ready to connect</Badge>
            ) : (
              <Badge variant="secondary">
                {provider?.reason === "authenticated_https_admin_required"
                  ? "Authenticated HTTPS required"
                  : "Connector not installed"}
              </Badge>
            )}
          </CardAction>
        </CardHeader>

        <CardContent>
          {cloudflareConnection ? (
            <ConnectedCloudflare
              connection={cloudflareConnection}
              refreshing={refreshStatus.isPending}
              disconnecting={disconnect.isPending}
              actionsDisabled={refreshStatus.isPending || disconnect.isPending}
              onRefresh={() => refreshStatus.mutate(cloudflareConnection.id)}
              onDisconnect={() => disconnect.mutate(cloudflareConnection.id)}
            />
          ) : authorization ? (
            <ProvisionForm
              authorization={authorization}
              accountId={accountId}
              zoneId={zoneId}
              hostname={hostname}
              pending={provision.isPending}
              onAccountChange={setAccountId}
              onZoneChange={setZoneId}
              onHostnameChange={setHostname}
              onBack={() => cancelAuthorization.mutate()}
              onSubmit={() =>
                provision.mutate({
                  account_id: accountId,
                  zone_id: zoneId,
                  hostname: hostname.trim(),
                })
              }
            />
          ) : (
            <AuthorizationForm
              available={available}
              permissions={setup.data?.required_permissions ?? []}
              reason={provider?.reason ?? null}
              error={pendingAuthorization.isError && !authorizationMissing}
              apiToken={apiToken}
              pending={authorizing}
              onTokenChange={setApiToken}
              onSubmit={() => void authorize()}
            />
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function TailscaleConnectionsPage() {
  const queryClient = useQueryClient()
  const [deviceName, setDeviceName] = useState("lns")
  const [login, setLogin] = useState<TailscaleLogin | null>(null)
  const [qrCode, setQrCode] = useState<string | null>(null)
  const [connecting, setConnecting] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [checking, setChecking] = useState(false)
  const [pollFailures, setPollFailures] = useState(0)
  const [proxyAccessDenied, setProxyAccessDenied] = useState(false)
  const operationInFlight = useRef<"check" | "connect" | "cancel" | null>(null)
  const recoveryAttempted = useRef(false)
  const connections = useQuery({ queryKey: ["connections"], queryFn: api.connections })
  const provider = connections.data?.providers.find((item) => item.id === "tailscale")
  const providerAvailable = provider?.capability === "available"
  const setup = useQuery({
    queryKey: ["tailscale-setup"],
    queryFn: api.tailscaleSetup,
    enabled: providerAvailable,
  })
  const connection = connections.data?.connections.find((item) => item.provider === "tailscale")
  const providerReason = provider?.reason ?? null
  const setupForbidden = setup.error instanceof ApiError && setup.error.status === 403
  const authenticatedProxyRequired =
    providerReason === "authenticated_https_admin_required" || setupForbidden || proxyAccessDenied
  const available = setup.data?.available === true && providerAvailable && !authenticatedProxyRequired
  const normalizedName = deviceName.trim().toLowerCase()
  const validName = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(normalizedName)

  const clearLoginView = useCallback(() => {
    setLogin(null)
    setQrCode(null)
    setPollFailures(0)
  }, [])

  const applyLoginResult = useCallback(
    async (result: TailscaleLogin) => {
      if (result.state === "expired") {
        clearLoginView()
        toast.error("Tailscale login expired. Start a new login.")
        return
      }
      setLogin(result)
      if (result.state === "connected") {
        setQrCode(null)
        await queryClient.invalidateQueries({ queryKey: ["connections"] })
        toast.success("Tailscale Funnel connected")
      }
    },
    [clearLoginView, queryClient],
  )

  const checkLogin = useCallback(
    async (announceError = true) => {
      if (operationInFlight.current !== null) return
      operationInFlight.current = "check"
      setChecking(true)
      try {
        await applyLoginResult(await api.tailscaleLoginStatus())
        setPollFailures(0)
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) {
          if (login !== null) {
            clearLoginView()
            toast.error("Tailscale login expired. Start a new login.")
          }
          return
        }
        if (error instanceof ApiError && error.status === 403) {
          clearLoginView()
          setProxyAccessDenied(true)
          toast.error(
            "Open lnSwitchboard through an authenticated HTTPS admin proxy to manage Tailscale.",
          )
          return
        }
        setPollFailures((value) => Math.min(value + 1, 4))
        if (announceError) {
          toast.error(
            error instanceof Error ? error.message : "Unable to check Tailscale login",
          )
        }
      } finally {
        if (operationInFlight.current === "check") operationInFlight.current = null
        setChecking(false)
      }
    },
    [applyLoginResult, clearLoginView, login],
  )

  useEffect(() => {
    if (setup.data?.default_device_name) setDeviceName(setup.data.default_device_name)
  }, [setup.data?.default_device_name])

  useEffect(() => {
    if (authenticatedProxyRequired) clearLoginView()
  }, [authenticatedProxyRequired, clearLoginView])

  useEffect(() => {
    if (!available || recoveryAttempted.current) return
    recoveryAttempted.current = true
    void checkLogin(false)
  }, [available, checkLogin])

  useEffect(() => {
    if (login?.state !== "needs_login") return
    const delay = Math.min(2_000 * 2 ** pollFailures, 30_000)
    const timeout = window.setTimeout(() => void checkLogin(false), delay)
    return () => window.clearTimeout(timeout)
  }, [checkLogin, login?.state, pollFailures])

  useEffect(() => {
    let active = true
    const authUrl = login?.state === "needs_login" ? login.auth_url : null
    if (!authUrl) {
      setQrCode(null)
      return
    }
    void QRCode.toString(authUrl, {
      type: "svg",
      errorCorrectionLevel: "M",
      margin: 1,
      width: 192,
    }).then((svg) => {
      if (active) setQrCode(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`)
    })
    return () => {
      active = false
    }
  }, [login])

  const connect = async () => {
    if (!available || !validName || operationInFlight.current !== null) return
    operationInFlight.current = "connect"
    setConnecting(true)
    try {
      await applyLoginResult(await api.beginTailscaleLogin(normalizedName))
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) {
        clearLoginView()
        setProxyAccessDenied(true)
        toast.error(
          "Open lnSwitchboard through an authenticated HTTPS admin proxy to manage Tailscale.",
        )
      } else {
        toast.error(error instanceof Error ? error.message : "Unable to start Tailscale login")
      }
    } finally {
      if (operationInFlight.current === "connect") operationInFlight.current = null
      setConnecting(false)
    }
  }

  const cancel = async () => {
    if (operationInFlight.current !== null) return
    operationInFlight.current = "cancel"
    setCancelling(true)
    try {
      await api.cancelTailscaleLogin()
      clearLoginView()
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) {
        clearLoginView()
        setProxyAccessDenied(true)
        toast.error(
          "Open lnSwitchboard through an authenticated HTTPS admin proxy to manage Tailscale.",
        )
      } else {
        toast.error(error instanceof Error ? error.message : "Unable to cancel Tailscale login")
      }
    } finally {
      if (operationInFlight.current === "cancel") operationInFlight.current = null
      setCancelling(false)
    }
  }

  const handleManagementError = (error: unknown, fallback: string) => {
    if (error instanceof ApiError && error.status === 403) {
      clearLoginView()
      setProxyAccessDenied(true)
      toast.error(
        "Open lnSwitchboard through an authenticated HTTPS admin proxy to manage Tailscale.",
      )
      return
    }
    toast.error(error instanceof Error ? error.message : fallback)
  }

  const refresh = useMutation({
    mutationFn: api.refreshTailscaleStatus,
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["connections"] }),
    onError: (error) => handleManagementError(error, "Status refresh failed"),
  })
  const disconnect = useMutation({
    mutationFn: api.disconnectTailscale,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Tailscale Funnel disconnected")
    },
    onError: (error) => handleManagementError(error, "Disconnect failed"),
  })

  if (connections.isPending || (providerAvailable && setup.isPending)) {
    return <ConnectionsSkeleton />
  }
  if (connections.isError || (providerAvailable && setup.isError && !setupForbidden)) {
    return <ConnectionsLoadError />
  }

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-start gap-3">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-foreground/5 ring-1 ring-foreground/10">
          <NetworkIcon className="size-6" />
        </div>
        <div className="min-w-0">
          <h1 className="font-heading text-2xl font-semibold tracking-tight text-balance">Connections</h1>
          <p className="mt-1 max-w-2xl text-sm leading-normal text-pretty text-muted-foreground">
            Authorize a dedicated Tailscale node, then expose only lnSwitchboard&apos;s isolated public listener through Funnel.
          </p>
        </div>
      </header>

      <Card aria-disabled={!available ? true : undefined}>
        <CardHeader>
          <div className="flex items-center gap-2">
            <NetworkIcon className="size-5" />
            <CardTitle><h2>Tailscale Funnel</h2></CardTitle>
          </div>
          <CardDescription className="max-w-2xl text-pretty">
            Uses a short-lived browser login. Public HTTPS traffic reaches only port 21212; the Tailscale hostname is discovered after login.
          </CardDescription>
          <CardAction>
            {!available ? (
              <Badge variant="secondary">
                {authenticatedProxyRequired ? "Authenticated HTTPS required" : "Connector not installed"}
              </Badge>
            ) : connection ? (
              <ConnectionStatusBadge status={connection.status} />
            ) : (
              <Badge variant="outline">Ready to connect</Badge>
            )}
          </CardAction>
        </CardHeader>
        <CardContent>
          {connection ? (
            <ConnectedTailscale
              connection={connection}
              refreshing={refresh.isPending}
              disconnecting={disconnect.isPending}
              managementDisabled={!available}
              authenticatedProxyRequired={authenticatedProxyRequired}
              onRefresh={() => refresh.mutate(connection.id)}
              onDisconnect={() => disconnect.mutate(connection.id)}
            />
          ) : login?.state === "needs_login" && login.auth_url ? (
            <TailscaleLoginPrompt
              authUrl={login.auth_url}
              qrCode={qrCode}
              expiresIn={login.expires_in_seconds ?? 0}
              checking={checking || connecting}
              cancelling={cancelling}
              onCheck={() => void checkLogin()}
              onCancel={() => void cancel()}
            />
          ) : login?.state === "prerequisites_required" ? (
            <TailscalePrerequisites
              hostname={login.hostname ?? "Tailscale hostname unavailable"}
              missing={login.missing_prerequisites ?? []}
              checking={checking || connecting}
              onCheck={() => void checkLogin()}
              onCancel={() => void cancel()}
              cancelling={cancelling}
            />
          ) : (
            <FieldGroup className="max-w-2xl">
              <Field>
                <FieldLabel htmlFor="tailscale-device-name">Device name</FieldLabel>
                <Input
                  id="tailscale-device-name"
                  value={deviceName}
                  maxLength={setup.data?.device_name_max_length ?? 63}
                  aria-invalid={!validName}
                  aria-describedby={!validName ? "tailscale-device-name-error" : undefined}
                  disabled={!available || connecting}
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  onChange={(event) => setDeviceName(event.target.value)}
                />
                <FieldDescription>
                  Suggested: lns. Use one DNS label with letters, numbers, or internal hyphens. Your public .ts.net hostname is discovered from Tailscale.
                </FieldDescription>
                {!validName ? (
                  <p id="tailscale-device-name-error" role="alert" className="text-sm text-destructive">
                    Use 1–63 letters, numbers, or internal hyphens.
                  </p>
                ) : null}
              </Field>
              <Button type="button" disabled={!available || !validName || connecting || checking || cancelling} onClick={() => void connect()}>
                <ShieldCheckIcon />
                {connecting ? "Starting login…" : "Connect Tailscale"}
              </Button>
              {!available ? (
                <p className="text-sm text-muted-foreground">
                  {authenticatedProxyRequired
                    ? "Open lnSwitchboard through an authenticated HTTPS admin proxy to use Tailscale onboarding."
                    : "Add the Tailscale sidecar to this deployment stack to enable onboarding."}
                </p>
              ) : null}
            </FieldGroup>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function TailscaleLoginPrompt({
  authUrl,
  qrCode,
  expiresIn,
  checking,
  cancelling,
  onCheck,
  onCancel,
}: {
  authUrl: string
  qrCode: string | null
  expiresIn: number
  checking: boolean
  cancelling: boolean
  onCheck: () => void
  onCancel: () => void
}) {
  return (
    <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_12rem] md:items-start">
      <div className="space-y-4">
        <div>
          <h3 className="font-medium">Finish login in Tailscale</h3>
          <p className="mt-1 max-w-xl text-sm leading-normal text-pretty text-muted-foreground">
            Open the one-time login page or scan the QR code, sign in, and approve this dedicated node. This page checks automatically.
          </p>
        </div>
        <a
          className="inline-flex items-center gap-2 text-sm font-medium text-primary underline-offset-4 hover:underline"
          href={authUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          Open Tailscale login <ExternalLinkIcon className="size-4" />
        </a>
        <p className="text-xs text-muted-foreground">Login expires in about {Math.max(0, Math.ceil(expiresIn / 60))} minutes.</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" disabled={checking || cancelling} onClick={onCheck}>
            {checking ? "Checking…" : "Check status"}
          </Button>
          <Button type="button" variant="ghost" disabled={cancelling || checking} onClick={onCancel}>
            <XIcon /> {cancelling ? "Cancelling…" : "Cancel"}
          </Button>
        </div>
      </div>
      <div className="flex aspect-square items-center justify-center overflow-hidden rounded-xl bg-white p-2 ring-1 ring-black/10">
        {qrCode ? (
          <img className="size-full" src={qrCode} alt="Tailscale login QR code" />
        ) : (
          <Skeleton className="size-full rounded-lg" />
        )}
      </div>
    </div>
  )
}

const prerequisiteLabels: Record<string, string> = {
  magic_dns: "Enable MagicDNS for the tailnet.",
  https_certificates: "Enable HTTPS certificates for the reported node hostname.",
  funnel_node_attribute: "Grant tag:lnswitchboard the funnel node attribute.",
  funnel_port_443: "Allow Funnel on HTTPS port 443.",
}

function TailscalePrerequisites({
  hostname,
  missing,
  checking,
  cancelling,
  onCheck,
  onCancel,
}: {
  hostname: string
  missing: string[]
  checking: boolean
  cancelling: boolean
  onCheck: () => void
  onCancel: () => void
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-medium">Tailnet setup required</h3>
        <p className="mt-1 text-sm text-muted-foreground">
          The node is signed in as <span className="font-medium text-foreground">{hostname}</span>. lnSwitchboard will not change tailnet policy automatically.
        </p>
      </div>
      <ul className="space-y-2 text-sm text-muted-foreground">
        {missing.map((item) => <li key={item}>• {prerequisiteLabels[item] ?? item}</li>)}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={checking || cancelling} onClick={onCheck}>
          {checking ? "Checking…" : "Check again"}
        </Button>
        <Button type="button" variant="ghost" disabled={cancelling || checking} onClick={onCancel}>
          {cancelling ? "Cancelling…" : "Disconnect node"}
        </Button>
      </div>
    </div>
  )
}

function ConnectedTailscale({
  connection,
  refreshing,
  disconnecting,
  managementDisabled,
  authenticatedProxyRequired,
  onRefresh,
  onDisconnect,
}: {
  connection: ProviderConnection
  refreshing: boolean
  disconnecting: boolean
  managementDisabled: boolean
  authenticatedProxyRequired: boolean
  onRefresh: () => void
  onDisconnect: () => void
}) {
  const disabled = managementDisabled || refreshing || disconnecting
  return (
    <div className="flex flex-col gap-5">
      {managementDisabled ? (
        <p role="alert" className="rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
          {authenticatedProxyRequired
            ? "Open lnSwitchboard through an authenticated HTTPS admin proxy to refresh or disconnect Tailscale."
            : "Restore the Tailscale connector to refresh or disconnect this connection."}
        </p>
      ) : null}
      {connection.domains.map((domain) => (
        <div key={domain.hostname} className="rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
          <div className="flex min-w-0 items-center justify-between gap-3">
            <span className="min-w-0 truncate font-medium" title={domain.hostname}>{domain.hostname}</span>
            <div className="flex shrink-0 items-center gap-2">
              <CopyButton
                value={domain.hostname}
                label="Copy hostname"
                copiedLabel="Hostname copied"
              />
              <Badge variant={domain.status === "error" ? "destructive" : "outline"}>{domain.status}</Badge>
            </div>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">Authoritative Tailscale hostname • Funnel HTTPS 443 → lnSwitchboard 21212</p>
          {domain.last_error ? (
            <p role="alert" className="mt-2 text-xs text-destructive">{domain.last_error}</p>
          ) : null}
        </div>
      ))}
      {connection.last_error ? <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{connection.last_error}</p> : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={disabled} onClick={onRefresh}>
          <RefreshCwIcon className={refreshing ? "animate-spin" : undefined} />
          {refreshing ? "Checking…" : "Refresh status"}
        </Button>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="destructive" disabled={disabled}>
              <Trash2Icon /> {disconnecting ? "Disconnecting…" : "Disconnect"}
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Disconnect Tailscale Funnel?</AlertDialogTitle>
              <AlertDialogDescription>
                lnSwitchboard will disable public Funnel ingress before logging out and removing its dedicated node state.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={onDisconnect}>Disconnect Funnel</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  )
}

function AuthorizationForm({
  available,
  permissions,
  reason,
  error,
  apiToken,
  pending,
  onTokenChange,
  onSubmit,
}: {
  available: boolean
  permissions: string[]
  reason: string | null
  error: boolean
  apiToken: string
  pending: boolean
  onTokenChange: (value: string) => void
  onSubmit: () => void
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.8fr)]">
      <div className="space-y-4">
        <div>
          <h3 className="font-medium">Connect with a scoped API token</h3>
          <p className="mt-1 max-w-xl text-sm leading-normal text-pretty text-muted-foreground">
            Create a least-privilege token in Cloudflare, then paste it here once. lnSwitchboard validates it over the private administrative connection and encrypts it immediately.
          </p>
        </div>
        <a
          className="text-sm font-medium text-primary underline-offset-4 hover:underline"
          href="https://dash.cloudflare.com/profile/api-tokens"
          target="_blank"
          rel="noreferrer"
        >
          Create a scoped token in Cloudflare
        </a>
        {error ? (
          <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
            Cloudflare authorization expired or could not be loaded. Validate the token again.
          </p>
        ) : null}
        <Field className="max-w-xl">
          <FieldLabel htmlFor="cloudflare-api-token">Cloudflare API token</FieldLabel>
          <Input
            id="cloudflare-api-token"
            type="password"
            value={apiToken}
            disabled={!available || pending}
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => onTokenChange(event.target.value)}
          />
          <FieldDescription>
            The token is never placed in a URL or browser storage and is cleared from this field after validation.
          </FieldDescription>
        </Field>
        <Button
          type="button"
          disabled={!available || pending || !apiToken.trim()}
          onClick={onSubmit}
        >
          <ShieldCheckIcon />
          {pending ? "Validating…" : "Validate token"}
        </Button>
        {!available ? (
          <p className="text-sm text-muted-foreground">
            {reason === "connector_not_installed"
              ? "Add the cloudflared connector service to this deployment stack to enable onboarding."
              : "Cloudflare onboarding is unavailable in this deployment."}
          </p>
        ) : null}
      </div>

      <div className="rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
        <div className="flex items-center gap-2 text-sm font-medium">
          <ShieldCheckIcon className="size-4" />
          Required token permissions
        </div>
        <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
          {permissions.map((permission) => (
            <li key={permission} className="flex gap-2">
              <span aria-hidden="true" className="mt-1.5 size-1.5 shrink-0 rounded-full bg-[#f38020]" />
              <span>{permission}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs leading-normal text-muted-foreground">
          Restrict the token to the Cloudflare account and zone you intend to connect.
        </p>
      </div>
    </div>
  )
}

function ProvisionForm({
  authorization,
  accountId,
  zoneId,
  hostname,
  pending,
  onAccountChange,
  onZoneChange,
  onHostnameChange,
  onBack,
  onSubmit,
}: {
  authorization: CloudflareAuthorization
  accountId: string
  zoneId: string
  hostname: string
  pending: boolean
  onAccountChange: (value: string) => void
  onZoneChange: (value: string) => void
  onHostnameChange: (value: string) => void
  onBack: () => void
  onSubmit: () => void
}) {
  const account = authorization.accounts.find((item) => item.id === accountId)
  const ready = Boolean(accountId && zoneId && hostname.trim())
  return (
    <FieldGroup className="max-w-2xl">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="cloudflare-account">Account</FieldLabel>
          <Select value={accountId} onValueChange={onAccountChange} disabled={pending}>
            <SelectTrigger id="cloudflare-account" className="w-full">
              <SelectValue placeholder="Select an account" />
            </SelectTrigger>
            <SelectContent>
              {authorization.accounts.map((item) => (
                <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="cloudflare-zone">Zone</FieldLabel>
          <Select value={zoneId} onValueChange={onZoneChange} disabled={pending || !account}>
            <SelectTrigger id="cloudflare-zone" className="w-full">
              <SelectValue placeholder="Select a zone" />
            </SelectTrigger>
            <SelectContent>
              {account?.zones.map((zone) => (
                <SelectItem key={zone.id} value={zone.id}>{zone.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      </div>
      {account && account.zones.length === 0 ? (
        <FieldDescription>
          This account has no active zones. Create and activate a zone in{" "}
          <a className="underline" href="https://dash.cloudflare.com/?to=/:account/websites" target="_blank" rel="noreferrer">
            Cloudflare Websites
          </a>{" "}
          then validate a fresh scoped token to discover it here.
        </FieldDescription>
      ) : null}
      <Field>
        <FieldLabel htmlFor="cloudflare-hostname">Public hostname</FieldLabel>
        <Input
          id="cloudflare-hostname"
          value={hostname}
          disabled={pending}
          placeholder="pay.example.com"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => onHostnameChange(event.target.value)}
        />
        <FieldDescription>
          lnSwitchboard checks this exact hostname in the selected zone before it creates an owned DNS record. Existing records are never overwritten.
        </FieldDescription>
      </Field>
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={!ready || pending} onClick={onSubmit}>
          {pending ? "Creating tunnel…" : "Create tunnel"}
        </Button>
        <Button type="button" variant="ghost" disabled={pending} onClick={onBack}>Back</Button>
      </div>
    </FieldGroup>
  )
}

function ConnectedCloudflare({
  connection,
  refreshing,
  disconnecting,
  actionsDisabled,
  onRefresh,
  onDisconnect,
}: {
  connection: ProviderConnection
  refreshing: boolean
  disconnecting: boolean
  actionsDisabled: boolean
  onRefresh: () => void
  onDisconnect: () => void
}) {
  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-3 sm:grid-cols-2">
        {connection.domains.map((domain) => (
          <div key={domain.hostname} className="rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
            <div className="flex items-center justify-between gap-3">
              <span className="truncate font-medium">{domain.hostname}</span>
              <Badge variant={domain.status === "error" ? "destructive" : "outline"}>{domain.status}</Badge>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">DNS and tunnel configuration managed by lnSwitchboard</p>
          </div>
        ))}
      </div>
      {connection.last_error ? (
        <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {connection.last_error}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={actionsDisabled} onClick={onRefresh}>
          <RefreshCwIcon className={refreshing ? "animate-spin" : undefined} />
          {refreshing ? "Checking…" : "Refresh status"}
        </Button>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="destructive" disabled={actionsDisabled}>
              <Trash2Icon />
              {disconnecting ? "Disconnecting…" : "Disconnect"}
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Disconnect Cloudflare Tunnel?</AlertDialogTitle>
              <AlertDialogDescription>
                lnSwitchboard will disable public ingress, remove its owned DNS record, and delete its managed tunnel. DNS records that no longer match are preserved.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={onDisconnect}>
                Disconnect tunnel
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  )
}

function ConnectionStatusBadge({ status }: { status: ProviderConnection["status"] }) {
  const variant = status === "error" ? "destructive" : status === "connected" ? "default" : "outline"
  return <Badge variant={variant}>{status}</Badge>
}

function ConnectionsLoadError() {
  return (
    <Card role="alert">
      <CardHeader>
        <CardTitle>Connections are unavailable</CardTitle>
        <CardDescription>
          lnSwitchboard could not load connection status. Refresh the page or check the server logs.
        </CardDescription>
      </CardHeader>
    </Card>
  )
}

function ConnectionsSkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-label="Loading connections">
      <div className="flex items-center gap-3">
        <Skeleton className="size-11 rounded-xl" />
        <div className="space-y-2">
          <Skeleton className="h-7 w-40" />
          <Skeleton className="h-4 w-72 max-w-full" />
        </div>
      </div>
      <Skeleton className="h-80 w-full rounded-xl" />
    </div>
  )
}
