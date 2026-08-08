import { useCallback, useEffect, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ExternalLinkIcon, PlusIcon, RefreshCwIcon, ShieldCheckIcon, Trash2Icon, XIcon } from "lucide-react"
import QRCode from "qrcode"
import { useLocation, useSearchParams } from "react-router"

import { toast } from "sonner"

import { CloudflareIcon } from "@/components/cloudflare-icon"
import { CopyButton } from "@/components/common"
import { TailscaleIcon } from "@/components/tailscale-icon"
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
  CardDescription,
  CardHeader,

  CardTitle,
} from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  ApiError,
  api,
  type CloudflareOAuthFlow,
  type CloudflareOAuthGrant,
  type CloudflareOAuthRedirectMode,
  type CloudflareZone,
  type ProviderConnection,
  type TailscaleLogin,
} from "@/lib/api"

export function ConnectionsPage() {
  const location = useLocation()
  return location.pathname.includes("/connections/tailscale") ? (
    <TailscaleConnectionsPage />
  ) : (
    <CloudflareConnectionsPage />
  )
}

type CloudflareStep = "connect" | "authorize" | "grant" | "provision"

function cloudflareFlowState(authorizeUrl: string): string {
  try {
    return new URL(authorizeUrl).searchParams.get("state") ?? ""
  } catch {
    return ""
  }
}

function grantExpiryLabel(grant: CloudflareOAuthGrant): string {
  if (grant.access_token_expires_at === null) {
    return grant.has_refresh_token ? "Renews automatically" : "No expiry recorded"
  }
  const expiry = new Date(grant.access_token_expires_at * 1000)
  if (Number.isNaN(expiry.getTime())) return "No expiry recorded"
  if (expiry.getTime() <= Date.now()) {
    return grant.has_refresh_token
      ? "Access token expired — renews automatically"
      : `Access token expired ${expiry.toLocaleString()}`
  }
  return `Access token expires ${expiry.toLocaleString()}`
}

function CloudflareConnectionsPage() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const [step, setStep] = useState<CloudflareStep>("connect")
  const [redirectMode, setRedirectMode] = useState<CloudflareOAuthRedirectMode>("loopback")
  const [flow, setFlow] = useState<CloudflareOAuthFlow | null>(null)
  const [code, setCode] = useState("")
  const [stateValue, setStateValue] = useState("")
  const [accountId, setAccountId] = useState("")
  const [zoneId, setZoneId] = useState("")
  const [hostname, setHostname] = useState("")
  const [pending, setPending] = useState<"begin" | "complete" | "authorize" | null>(null)
  const [reconnectNotice, setReconnectNotice] = useState<string | null>(null)

  const connections = useQuery({ queryKey: ["connections"], queryFn: api.connections })
  const setup = useQuery({ queryKey: ["cloudflare-setup"], queryFn: api.cloudflareSetup })
  const cloudflareConnection = connections.data?.connections.find(
    (connection) => connection.provider === "cloudflare",
  )
  const provider = connections.data?.providers.find((item) => item.id === "cloudflare")
  const available = setup.data?.available === true && provider?.capability === "available"
  const onboarding = !cloudflareConnection || reconnectNotice !== null
  const pendingAuthorization = useQuery({
    queryKey: ["cloudflare-authorization"],
    queryFn: api.cloudflareAuthorization,
    enabled: available && onboarding,
    retry: false,
  })
  const authorization = pendingAuthorization.data ?? null
  const grants = useQuery({
    queryKey: ["cloudflare-oauth-grants"],
    queryFn: api.cloudflareOAuthGrants,
    enabled: available && onboarding && !authorization && step === "grant",
    retry: false,
  })
  const availableDomains = useQuery({
    queryKey: ["cloudflare-available-domains", cloudflareConnection?.id],
    queryFn: () => api.availableCloudflareDomains(cloudflareConnection!.id),
    enabled: available && Boolean(cloudflareConnection) && reconnectNotice === null,
    retry: false,
  })
  const authorizationMissing =
    pendingAuthorization.error instanceof ApiError && pendingAuthorization.error.status === 404

  useEffect(() => {
    const result = searchParams.get("cloudflare")
    if (!result) return
    if (result === "connected") {
      setStep("grant")
      void queryClient.invalidateQueries({ queryKey: ["cloudflare-oauth-grants"] })
      toast.success("Cloudflare authorization received")
    } else {
      toast.error("Cloudflare authorization failed or was cancelled. Try again.")
    }
    const next = new URLSearchParams(searchParams)
    next.delete("cloudflare")
    setSearchParams(next, { replace: true })
  }, [searchParams, setSearchParams, queryClient])

  const begin = async () => {
    if (!available || pending !== null) return
    setPending("begin")
    try {
      const nextFlow = await api.beginCloudflareOAuth(redirectMode)
      setFlow(nextFlow)
      setStateValue(cloudflareFlowState(nextFlow.authorize_url))
      setCode("")
      setStep("authorize")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to start Cloudflare authorization")
    } finally {
      setPending(null)
    }
  }

  const complete = async () => {
    const pastedCode = code.trim()
    const pastedState = stateValue.trim()
    if (!pastedCode || !pastedState || pending !== null) return
    setPending("complete")
    try {
      await api.completeCloudflareOAuth({ code: pastedCode, state: pastedState })
      setFlow(null)
      setStep("grant")
      await queryClient.invalidateQueries({ queryKey: ["cloudflare-oauth-grants"] })
      toast.success("Cloudflare authorization received")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Cloudflare authorization failed")
    } finally {
      setCode("")
      setStateValue("")
      setPending(null)
    }
  }

  const selectGrant = async (grant: CloudflareOAuthGrant) => {
    if (pending !== null) return
    const grantAccountId =
      typeof grant.account_metadata.account_id === "string" ? grant.account_metadata.account_id : ""
    if (!grantAccountId) {
      toast.error("This authorization is missing its Cloudflare account. Delete it and reconnect Cloudflare.")
      return
    }
    setPending("authorize")
    try {
      const result = await api.authorizeCloudflare({ grant_id: grant.grant_id, account_id: grantAccountId })
      const account = result.accounts.find((item) => item.id === grantAccountId) ?? result.accounts[0]
      if (!account) throw new Error("Cloudflare returned no accounts for this authorization.")
      queryClient.setQueryData(["cloudflare-authorization"], result)
      setAccountId(account.id)
      setZoneId(account.zones[0]?.id ?? "")
      setHostname(account.zones[0]?.name ?? "")
      setStep("provision")
      toast.success("Cloudflare account access confirmed")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Cloudflare authorization failed")
    } finally {
      setPending(null)
    }
  }

  const resetOnboarding = (nextStep: CloudflareStep) => {
    setFlow(null)
    setCode("")
    setStateValue("")
    setStep(nextStep)
  }

  const provision = useMutation({
    mutationFn: api.provisionCloudflare,
    onSuccess: async () => {
      queryClient.removeQueries({ queryKey: ["cloudflare-authorization"] })
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
      resetOnboarding("connect")
      setReconnectNotice(null)
      toast.success("Cloudflare connection is provisioning")
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Cloudflare provisioning failed"),
  })

  const cancelAuthorization = useMutation({
    mutationFn: api.cancelCloudflareAuthorization,
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: ["cloudflare-authorization"] })
      setStep("grant")
    },
    onError: (error) =>
      toast.error(
        error instanceof Error ? error.message : "Unable to cancel authorization",
      ),
  })

  const deleteGrant = useMutation({
    mutationFn: api.deleteCloudflareOAuthGrant,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["cloudflare-oauth-grants"] })
      toast.success("Cloudflare authorization removed")
    },
    onError: (error) =>
      toast.error(error instanceof Error ? error.message : "Unable to remove authorization"),
  })

  const handleManagementError = (error: unknown, fallback: string) => {
    if (error instanceof ApiError && error.status === 409 && /reconnect/i.test(error.message)) {
      setReconnectNotice(error.message)
      resetOnboarding("connect")
    }
    toast.error(error instanceof Error ? error.message : fallback)
  }

  const refreshStatus = useMutation({
    mutationFn: api.refreshCloudflareStatus,
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["connections"] }),
    onError: (error) => handleManagementError(error, "Status refresh failed"),
  })

  const disconnect = useMutation({
    mutationFn: api.disconnectCloudflare,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["connections"] })
      toast.success("Cloudflare disconnected")
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Disconnect failed"),
  })

  const addDomain = useMutation({
    mutationFn: (payload: { connectionId: string; zoneId: string; hostname: string }) =>
      api.addCloudflareDomain(payload),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["connections"] }),
        queryClient.invalidateQueries({ queryKey: ["cloudflare-available-domains"] }),
      ])
      toast.success("Cloudflare domain added")
    },
    onError: (error) => handleManagementError(error, "Unable to add domain"),
  })

  const removeDomain = useMutation({
    mutationFn: (payload: { connectionId: string; hostname: string }) =>
      api.removeCloudflareDomain(payload),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["connections"] }),
        queryClient.invalidateQueries({ queryKey: ["cloudflare-available-domains"] }),
      ])
      toast.success("Cloudflare domain removed")
    },
    onError: (error) => handleManagementError(error, "Unable to remove domain"),
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
      <section
        aria-disabled={onboardingDisabled || undefined}
        className={onboardingDisabled ? "opacity-75" : undefined}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-center gap-2">
              <CloudflareIcon className="size-5" />
              <h2 className="font-heading text-xl font-semibold tracking-tight">Cloudflare</h2>
            </div>
            <p className="max-w-2xl text-sm text-pretty text-muted-foreground">
              Connect your Cloudflare account to publish Lightning Addresses on your own domains. Authorization happens entirely between you and Cloudflare; tokens never leave this device.
            </p>
          </div>
          <div className="shrink-0">
            {cloudflareConnection ? (
              <ConnectionStatusBadge status={cloudflareConnection.status} />
            ) : available ? (
              <Badge variant="outline">Ready to connect</Badge>
            ) : (
              <Badge variant="secondary">
                {setup.data?.oauth_configured === false ? "OAuth not configured" : "Connector not installed"}
              </Badge>
            )}
          </div>
        </div>

        <div className="mt-6">
          {setup.data?.configuration_error ? (
            <p role="alert" className="mb-4 rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {setup.data.configuration_error}
            </p>
          ) : null}
          {cloudflareConnection && reconnectNotice === null ? (
            <ConnectedCloudflare
              connection={cloudflareConnection}
              availableZones={availableDomains.data?.zones ?? []}
              refreshing={refreshStatus.isPending}
              disconnecting={disconnect.isPending}
              addingDomain={addDomain.isPending}
              removingDomain={removeDomain.isPending}
              actionsDisabled={
                refreshStatus.isPending ||
                disconnect.isPending ||
                addDomain.isPending ||
                removeDomain.isPending
              }
              onRefresh={() => refreshStatus.mutate(cloudflareConnection.id)}
              onAddDomain={(selectedZoneId, selectedHostname) =>
                addDomain.mutate({
                  connectionId: cloudflareConnection.id,
                  zoneId: selectedZoneId,
                  hostname: selectedHostname,
                })
              }
              onRemoveDomain={(selectedHostname) =>
                removeDomain.mutate({
                  connectionId: cloudflareConnection.id,
                  hostname: selectedHostname,
                })
              }
              onDisconnect={() => disconnect.mutate(cloudflareConnection.id)}
            />
          ) : (
            <div className="flex flex-col gap-5">
              {reconnectNotice !== null ? (
                <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {reconnectNotice} Reconnect Cloudflare below to restore domain management.
                </p>
              ) : null}
              {authorization ? (
                <CloudflareProvisionForm
                  accounts={authorization.accounts}
                  accountId={accountId}
                  zoneId={zoneId}
                  hostname={hostname}
                  pending={provision.isPending}
                  onAccountChange={(nextAccountId) => {
                    setAccountId(nextAccountId)
                    const nextAccount = authorization.accounts.find((account) => account.id === nextAccountId)
                    setZoneId(nextAccount?.zones[0]?.id ?? "")
                    setHostname(nextAccount?.zones[0]?.name ?? "")
                  }}
                  onZoneChange={(nextZoneId) => {
                    setZoneId(nextZoneId)
                    const nextZone = authorization.accounts
                      .find((account) => account.id === accountId)
                      ?.zones.find((zone) => zone.id === nextZoneId)
                    if (nextZone) setHostname(nextZone.name)
                  }}
                  onHostnameChange={setHostname}
                  onBack={() => cancelAuthorization.mutate()}
                  onSubmit={() => {
                    const account = authorization.accounts.find((item) => item.id === accountId)
                    const zone = account?.zones.find((item) => item.id === zoneId)
                    if (!account || !zone) return
                    provision.mutate({
                      account_id: account.id,
                      zone_id: zone.id,
                      hostname,
                    })
                  }}
                />
              ) : step === "grant" ? (
                <CloudflareGrantPicker
                  grants={grants.data?.grants ?? []}
                  loading={grants.isPending}
                  error={grants.error instanceof Error ? grants.error.message : null}
                  pending={pending !== null}
                  deleting={deleteGrant.isPending}
                  onSelect={(grant) => void selectGrant(grant)}
                  onDelete={(grantId) => deleteGrant.mutate(grantId)}
                  onConnect={() => resetOnboarding("connect")}
                />
              ) : step === "authorize" && flow ? (
                <CloudflareAwaitingAuthorization
                  authorizeUrl={flow.authorize_url}
                  expiresAt={flow.expires_at}
                  code={code}
                  stateValue={stateValue}
                  pending={pending !== null}
                  onCodeChange={setCode}
                  onStateChange={setStateValue}
                  onComplete={() => void complete()}
                  onCancel={() => resetOnboarding("connect")}
                />
              ) : (
                <CloudflareConnect
                  available={available}
                  permissions={setup.data?.required_permissions ?? []}
                  reason={provider?.reason ?? null}
                  authorizationFailed={pendingAuthorization.isError && !authorizationMissing}
                  redirectMode={redirectMode}
                  pending={pending !== null}
                  onRedirectModeChange={setRedirectMode}
                  onSubmit={() => void begin()}
                />
              )}
            </div>
          )}
        </div>
      </section>
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
  const available = setup.data?.available === true && providerAvailable
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
      toast.error(error instanceof Error ? error.message : "Unable to start Tailscale login")
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
      toast.error(error instanceof Error ? error.message : "Unable to cancel Tailscale login")
    } finally {
      if (operationInFlight.current === "cancel") operationInFlight.current = null
      setCancelling(false)
    }
  }

  const handleManagementError = (error: unknown, fallback: string) => {
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
  if (connections.isError || (providerAvailable && setup.isError)) {
    return <ConnectionsLoadError />
  }

  return (
    <div className="flex flex-col gap-6">
      <section aria-disabled={!available ? true : undefined}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-center gap-2">
              <TailscaleIcon className="size-5" />
              <h2 className="font-heading text-xl font-semibold tracking-tight">Tailscale Funnel</h2>
            </div>
            <p className="max-w-2xl text-sm text-pretty text-muted-foreground">
              Use Tailscale Funnel to make your Lightning Addresses available on the web. Connect your Tailscale account, then share the hostname it gives you.
            </p>
          </div>
          <div className="shrink-0">
            {!available ? (
              <Badge variant="secondary">
                Connector not installed
              </Badge>
            ) : connection ? (
              <ConnectionStatusBadge status={connection.status} />
            ) : (
              <Badge variant="outline">Ready to connect</Badge>
            )}
          </div>
        </div>
        <div className="mt-6">
          {connection ? (
            <ConnectedTailscale
              connection={connection}
              refreshing={refresh.isPending}
              disconnecting={disconnect.isPending}
              managementDisabled={!available}
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
                  Add the Tailscale sidecar to this deployment stack to enable onboarding.
                </p>
              ) : null}
            </FieldGroup>
          )}
        </div>
      </section>
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
  funnel_node_attribute: "Grant this node (or an operator-chosen tag) the Funnel node attribute.",
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
  onRefresh,
  onDisconnect,
}: {
  connection: ProviderConnection
  refreshing: boolean
  disconnecting: boolean
  managementDisabled: boolean
  onRefresh: () => void
  onDisconnect: () => void
}) {
  const disabled = managementDisabled || refreshing || disconnecting
  const keyExpiryEnabled = connection.public_metadata.key_expiry_enabled === true
  const keyExpiryDays = connection.public_metadata.key_expiry_days_remaining
  const daysRemaining = typeof keyExpiryDays === "number" && Number.isFinite(keyExpiryDays) ? Math.max(0, Math.ceil(keyExpiryDays)) : null
  return (
    <div className="flex flex-col gap-5">
      {managementDisabled ? (
        <p role="alert" className="rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
          Restore the Tailscale connector to refresh or disconnect this connection.
        </p>
      ) : null}
      {keyExpiryEnabled ? (
        <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-foreground">
          <span className="font-medium">Tailscale key expiry is enabled.</span>{" "}
          Disable key expiry for this device in the Tailscale admin console{daysRemaining !== null ? `, or reconnect Tailscale in ${daysRemaining} ${daysRemaining === 1 ? "day" : "days"}.` : "."}
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
            </div>
          </div>
          {domain.status === "active" ? (
            <p className="mt-2 text-sm text-muted-foreground">Your Lightning Addresses are available at this hostname.</p>
          ) : null}
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

function CloudflareConnect({
  available,
  permissions,
  reason,
  authorizationFailed,
  redirectMode,
  pending,
  onRedirectModeChange,
  onSubmit,
}: {
  available: boolean
  permissions: string[]
  reason: string | null
  authorizationFailed: boolean
  redirectMode: CloudflareOAuthRedirectMode
  pending: boolean
  onRedirectModeChange: (value: CloudflareOAuthRedirectMode) => void
  onSubmit: () => void
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.8fr)]">
      <div className="space-y-4">
        <div>
          <h3 className="font-medium">Connect your Cloudflare account</h3>
          <p className="mt-1 max-w-xl text-sm leading-normal text-pretty text-muted-foreground">
            lnSwitchboard opens Cloudflare’s authorization page, where you sign in and approve access. Authorization happens entirely between you and Cloudflare; tokens never leave this device.
          </p>
        </div>
        {authorizationFailed ? (
          <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
            Cloudflare authorization expired or could not be loaded. Connect again.
          </p>
        ) : null}
        <Field className="max-w-xl">
          <FieldLabel htmlFor="cloudflare-redirect-mode">Completion method</FieldLabel>
          <select
            id="cloudflare-redirect-mode"
            value={redirectMode}
            disabled={!available || pending}
            onChange={(event) => onRedirectModeChange(event.target.value === "page" ? "page" : "loopback")}
            className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs outline-none md:text-sm"
          >
            <option value="loopback">Return here automatically (this device)</option>
            <option value="page">Show a code to paste back (other devices)</option>
          </select>
          <FieldDescription>
            Automatic return works when you browse this admin panel on the machine that runs lnSwitchboard. Choose paste-back when you browse from another device on your network.
          </FieldDescription>
        </Field>
        <Button
          type="button"
          disabled={!available || pending}
          onClick={onSubmit}
        >
          <ShieldCheckIcon />
          {pending ? "Contacting Cloudflare…" : "Connect Cloudflare"}
        </Button>
        {!available ? (
          <p className="text-sm text-muted-foreground">
            {reason === "connector_not_installed"
              ? "Add the Cloudflare connector service to this deployment stack to enable onboarding."
              : "Cloudflare onboarding is unavailable in this deployment."}
          </p>
        ) : null}
      </div>

      <div className="rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
        <div className="flex items-center gap-2 text-sm font-medium">
          <ShieldCheckIcon className="size-4" />
          Cloudflare will request these permissions
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
          Review them on Cloudflare’s consent screen before approving. You can revoke access at any time in your Cloudflare profile.
        </p>
      </div>
    </div>
  )
}

function CloudflareAwaitingAuthorization({
  authorizeUrl,
  expiresAt,
  code,
  stateValue,
  pending,
  onCodeChange,
  onStateChange,
  onComplete,
  onCancel,
}: {
  authorizeUrl: string
  expiresAt: number
  code: string
  stateValue: string
  pending: boolean
  onCodeChange: (value: string) => void
  onStateChange: (value: string) => void
  onComplete: () => void
  onCancel: () => void
}) {
  const expiresAtDate = new Date(expiresAt * 1000)
  const expiresLabel = Number.isNaN(expiresAtDate.getTime()) ? null : expiresAtDate.toLocaleTimeString()
  return (
    <FieldGroup className="max-w-2xl">
      <div>
        <h3 className="font-medium">Finish authorization in Cloudflare</h3>
        <p className="mt-1 max-w-xl text-sm leading-normal text-pretty text-muted-foreground">
          Open the authorization page, sign in to Cloudflare, and approve the requested permissions. This page finishes automatically when you are redirected back here.
        </p>
      </div>
      <a
        className="inline-flex items-center gap-2 text-sm font-medium text-primary underline-offset-4 hover:underline"
        href={authorizeUrl}
        target="_blank"
        rel="noopener noreferrer"
      >
        Open Cloudflare authorization <ExternalLinkIcon className="size-4" />
      </a>
      {expiresLabel ? (
        <p className="text-xs text-muted-foreground">This link expires at {expiresLabel}.</p>
      ) : null}
      <Field>
        <FieldLabel htmlFor="cloudflare-oauth-code">Authorization code</FieldLabel>
        <Input
          id="cloudflare-oauth-code"
          value={code}
          disabled={pending}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => onCodeChange(event.target.value)}
        />
        <FieldDescription>
          If the page did not redirect back automatically, paste the code shown after authorizing.
        </FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor="cloudflare-oauth-state">State</FieldLabel>
        <Input
          id="cloudflare-oauth-state"
          value={stateValue}
          disabled={pending}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => onStateChange(event.target.value)}
        />
        <FieldDescription>
          Shown under the code on the Cloudflare callback page. It is filled in for you when available.
        </FieldDescription>
      </Field>
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={pending || !code.trim() || !stateValue.trim()} onClick={onComplete}>
          {pending ? "Completing…" : "Complete authorization"}
        </Button>
        <Button type="button" variant="ghost" disabled={pending} onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </FieldGroup>
  )
}

function CloudflareGrantPicker({
  grants,
  loading,
  error,
  pending,
  deleting,
  onSelect,
  onDelete,
  onConnect,
}: {
  grants: CloudflareOAuthGrant[]
  loading: boolean
  error: string | null
  pending: boolean
  deleting: boolean
  onSelect: (grant: CloudflareOAuthGrant) => void
  onDelete: (grantId: string) => void
  onConnect: () => void
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-medium">Choose a Cloudflare authorization</h3>
        <p className="mt-1 max-w-xl text-sm leading-normal text-pretty text-muted-foreground">
          Each authorization below is a consent grant stored on this device — never a token in your browser. Pick one to continue, or connect again.
        </p>
      </div>
      {loading ? (
        <div className="space-y-2" aria-label="Loading Cloudflare authorizations">
          <Skeleton className="h-20 w-full max-w-2xl rounded-xl" />
          <Skeleton className="h-20 w-full max-w-2xl rounded-xl" />
        </div>
      ) : error ? (
        <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>
      ) : grants.length === 0 ? (
        <p className="text-sm text-muted-foreground">No Cloudflare authorizations yet. Connect Cloudflare to create one.</p>
      ) : (
        <div className="grid gap-3">
          {grants.map((grant) => (
            <div key={grant.grant_id} className="max-w-2xl rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
              <div className="flex min-w-0 items-center justify-between gap-3">
                <span className="min-w-0 truncate font-medium">
                  {grant.account_label ?? "Cloudflare account"}
                </span>
                <Badge variant="outline">{grant.has_refresh_token ? "renews" : "one-time"}</Badge>
              </div>
              {grant.scopes ? (
                <p className="mt-2 text-xs break-words text-muted-foreground">{grant.scopes}</p>
              ) : null}
              <p className="mt-1 text-xs text-muted-foreground">{grantExpiryLabel(grant)}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button type="button" disabled={pending || deleting} onClick={() => onSelect(grant)}>
                  {pending ? "Authorizing…" : "Use this authorization"}
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      aria-label={`Delete authorization for ${grant.account_label ?? "Cloudflare account"}`}
                      disabled={pending || deleting}
                    >
                      <Trash2Icon />
                      Delete
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete this Cloudflare authorization?</AlertDialogTitle>
                      <AlertDialogDescription>
                        lnSwitchboard removes the stored grant from this device and asks Cloudflare to revoke it. You can reconnect Cloudflare at any time.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction variant="destructive" onClick={() => onDelete(grant.grant_id)}>
                        Delete authorization
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </div>
          ))}
        </div>
      )}
      <div>
        <Button type="button" variant="outline" disabled={pending} onClick={onConnect}>
          Connect Cloudflare again
        </Button>
      </div>
    </div>
  )
}

function CloudflareProvisionForm({
  accounts,
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
  accounts: Array<{ id: string; name: string; zones: Array<{ id: string; name: string }> }>
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
  const selectedAccount = accounts.find((account) => account.id === accountId) ?? accounts[0]
  const zones = selectedAccount?.zones ?? []
  const selectedZone = zones.find((zone) => zone.id === zoneId)
  const normalizedHostname = hostname.trim().toLowerCase().replace(/\.$/, "")
  const hostnameAuthorized = Boolean(selectedZone) && (
    normalizedHostname === selectedZone!.name || normalizedHostname.endsWith(`.${selectedZone!.name}`)
  )
  return (
    <FieldGroup className="max-w-2xl">
      <Field>
        <FieldLabel htmlFor="cloudflare-account">Cloudflare account</FieldLabel>
        <select
          id="cloudflare-account"
          value={selectedAccount?.id ?? ""}
          disabled={pending || accounts.length < 2}
          onChange={(event) => onAccountChange(event.target.value)}
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs outline-none md:text-sm"
        >
          {accounts.map((account) => <option key={account.id} value={account.id}>{account.name}</option>)}
        </select>
        <FieldDescription>The account you approved on Cloudflare’s consent screen.</FieldDescription>
      </Field>
      {zones.length === 0 ? (
        <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
          This authorization has no active DNS zones. Add a zone to the Cloudflare account, then authorize again.
        </p>
      ) : (
        <Field>
          <FieldLabel htmlFor="cloudflare-zone">Domain</FieldLabel>
          <select id="cloudflare-zone" value={zoneId} disabled={pending} onChange={(event) => onZoneChange(event.target.value)} className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs outline-none md:text-sm">
            {zones.map((zone) => <option key={zone.id} value={zone.id}>{zone.name}</option>)}
          </select>
          <FieldDescription>Select the Cloudflare zone that authorizes the hostname below.</FieldDescription>
        </Field>
      )}
      <Field data-invalid={!hostnameAuthorized || undefined}>
        <FieldLabel htmlFor="cloudflare-hostname">Hostname</FieldLabel>
        <Input id="cloudflare-hostname" value={hostname} disabled={pending || zones.length === 0} aria-invalid={!hostnameAuthorized} autoCapitalize="none" autoCorrect="off" spellCheck={false} onChange={(event) => onHostnameChange(event.target.value)} />
        <FieldDescription>Use the zone apex or a subdomain, such as pay.{selectedZone?.name ?? "example.com"}. Only the LNURL-pay and NIP-05 paths are published.</FieldDescription>
        {!hostnameAuthorized ? <p role="alert" className="text-sm text-destructive">Hostname must be the selected zone or one of its subdomains.</p> : null}
      </Field>
      <div className="flex flex-wrap gap-2"><Button type="button" disabled={!selectedZone || !hostnameAuthorized || pending} onClick={onSubmit}>{pending ? "Provisioning…" : "Create connection"}</Button><Button type="button" variant="ghost" disabled={pending} onClick={onBack}>Back</Button></div>
    </FieldGroup>
  )
}

function ConnectedCloudflare({
  connection,
  availableZones,
  refreshing,
  disconnecting,
  addingDomain,
  removingDomain,
  actionsDisabled,
  onRefresh,
  onAddDomain,
  onRemoveDomain,
  onDisconnect,
}: {
  connection: ProviderConnection
  availableZones: CloudflareZone[]
  refreshing: boolean
  disconnecting: boolean
  addingDomain: boolean
  removingDomain: boolean
  actionsDisabled: boolean
  onRefresh: () => void
  onAddDomain: (zoneId: string, hostname: string) => void
  onRemoveDomain: (hostname: string) => void
  onDisconnect: () => void
}) {
  const [showAddDomain, setShowAddDomain] = useState(false)
  const [selectedZoneId, setSelectedZoneId] = useState("")
  const [selectedHostname, setSelectedHostname] = useState("")
  const selectedZone = availableZones.find((zone) => zone.id === selectedZoneId)
  const normalizedHostname = selectedHostname.trim().toLowerCase().replace(/\.$/, "")
  const hostnameAuthorized = Boolean(selectedZone) && (
    normalizedHostname === selectedZone!.name || normalizedHostname.endsWith(`.${selectedZone!.name}`)
  )

  const beginAddingDomain = () => {
    const firstZone = availableZones[0]
    setSelectedZoneId(firstZone?.id ?? "")
    setSelectedHostname(firstZone?.name ?? "")
    setShowAddDomain(true)
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-3 sm:grid-cols-2">
        {connection.domains.map((domain) => (
          <div key={domain.hostname} className="rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
            <div className="flex items-center justify-between gap-3">
              <span className="min-w-0 truncate font-medium" title={domain.hostname}>{domain.hostname}</span>
              <div className="flex shrink-0 items-center gap-2">
                <Badge variant={domain.status === "error" ? "destructive" : "outline"}>{domain.status}</Badge>
                {connection.domains.length > 1 && domain.zone_id ? (
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button
                        type="button"
                        variant="ghost"
                        aria-label={`Remove ${domain.hostname}`}
                        disabled={actionsDisabled}
                      >
                        <Trash2Icon />
                        Remove
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Remove {domain.hostname}?</AlertDialogTitle>
                        <AlertDialogDescription>
                          lnSwitchboard will remove only this hostname’s LNURL-pay and NIP-05 routes. DNS created by lnSwitchboard will be removed; adopted DNS will be preserved. Your other domains stay connected.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                          variant="destructive"
                          disabled={removingDomain}
                          onClick={() => onRemoveDomain(domain.hostname)}
                        >
                          Remove domain
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                ) : null}
              </div>
            </div>
            {domain.status === "active" ? (
              <p className="mt-2 text-xs text-muted-foreground">Your Lightning Addresses are available at this hostname.</p>
            ) : null}
            {domain.last_error ? <p role="alert" className="mt-2 text-xs text-destructive">{domain.last_error}</p> : null}
          </div>
        ))}
      </div>
      {showAddDomain && availableZones.length > 0 ? (
        <FieldGroup className="max-w-2xl rounded-xl bg-muted/50 p-4 ring-1 ring-foreground/10">
          <Field>
            <FieldLabel htmlFor="cloudflare-additional-domain">Additional domain</FieldLabel>
            <select
              id="cloudflare-additional-domain"
              value={selectedZoneId}
              disabled={addingDomain}
              onChange={(event) => {
                const nextZoneId = event.target.value
                setSelectedZoneId(nextZoneId)
                const nextZone = availableZones.find((zone) => zone.id === nextZoneId)
                if (nextZone) setSelectedHostname(nextZone.name)
              }}
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs outline-none md:text-sm"
            >
              {availableZones.map((zone) => <option key={zone.id} value={zone.id}>{zone.name}</option>)}
            </select>
            <FieldDescription>
              Select the Cloudflare zone that authorizes the hostname below.
            </FieldDescription>
          </Field>
          <Field data-invalid={!hostnameAuthorized || undefined}>
            <FieldLabel htmlFor="cloudflare-additional-hostname">Hostname</FieldLabel>
            <Input id="cloudflare-additional-hostname" value={selectedHostname} disabled={addingDomain} aria-invalid={!hostnameAuthorized} autoCapitalize="none" autoCorrect="off" spellCheck={false} onChange={(event) => setSelectedHostname(event.target.value)} />
            <FieldDescription>Use the zone apex or a subdomain, such as pay.{selectedZone?.name ?? "example.com"}.</FieldDescription>
            {!hostnameAuthorized ? <p role="alert" className="text-sm text-destructive">Hostname must be the selected zone or one of its subdomains.</p> : null}
          </Field>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              disabled={!selectedZoneId || !hostnameAuthorized || addingDomain}
              onClick={() => {
                onAddDomain(selectedZoneId, normalizedHostname)
                setShowAddDomain(false)
              }}
            >
              {addingDomain ? "Adding domain…" : "Add selected domain"}
            </Button>
            <Button type="button" variant="ghost" disabled={addingDomain} onClick={() => setShowAddDomain(false)}>
              Cancel
            </Button>
          </div>
        </FieldGroup>
      ) : null}
      {connection.last_error ? (
        <p role="alert" className="rounded-lg bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {connection.last_error}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {availableZones.length > 0 && !showAddDomain ? (
          <Button type="button" disabled={actionsDisabled} onClick={beginAddingDomain}>
            <PlusIcon />
            Add Domain
          </Button>
        ) : null}
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
              <AlertDialogTitle>Disconnect Cloudflare?</AlertDialogTitle>
              <AlertDialogDescription>
                lnSwitchboard will remove every managed public route and owned DNS record. Adopted or changed DNS records are preserved.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={onDisconnect}>
                Disconnect
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
