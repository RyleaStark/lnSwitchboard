import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RefreshCwIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react"

import { toast } from "sonner"

import { CloudflareIcon } from "@/components/cloudflare-icon"
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
import { ApiError, api, type CloudflareAuthorization, type ProviderConnection } from "@/lib/api"

export function ConnectionsPage() {
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
  const pendingAuthorization = useQuery({
    queryKey: ["cloudflare-authorization"],
    queryFn: api.cloudflareAuthorization,
    enabled: setup.data?.available === true && !cloudflareConnection,
    retry: false,
  })
  const authorization = pendingAuthorization.data ?? null
  const provider = connections.data?.providers.find((item) => item.id === "cloudflare")
  const available = setup.data?.available === true && provider?.capability === "available"
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
                Connector not installed
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
          Existing DNS records are never overwritten. A conflict stops onboarding without changing the record.
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
