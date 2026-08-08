import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { EyeIcon, EyeOffIcon, KeyRoundIcon, RadioTowerIcon, SaveIcon, ServerCogIcon } from "lucide-react"
import { toast } from "sonner"

import { LoadingRows, PageError, PageHeader } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { api, type AuthStatus, type EnvSetting } from "@/lib/api"
import { shortHash } from "@/lib/format"

const settingsTabs = [
  { value: "auth", label: "Macaroon", icon: KeyRoundIcon },
  { value: "nostr", label: "Zap signer", icon: RadioTowerIcon },
  { value: "env", label: "Environment", icon: ServerCogIcon },
] as const

type SettingsTab = (typeof settingsTabs)[number]["value"]

const hiddenEnvSettingKeys = new Set(["DEP_ENV"])

export function SettingsPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<SettingsTab>("auth")
  const [macaroon, setMacaroon] = useState("")
  const [showMacaroon, setShowMacaroon] = useState(false)
  const [macaroonOpen, setMacaroonOpen] = useState(false)
  const [macaroonError, setMacaroonError] = useState("")
  const [zapPrivateKey, setZapPrivateKey] = useState("")
  const [showZapPrivateKey, setShowZapPrivateKey] = useState(false)
  const [zapSignerError, setZapSignerError] = useState("")
  const [draftValues, setDraftValues] = useState<Record<string, string>>({})
  const auth = useQuery({ queryKey: ["auth-status"], queryFn: api.authStatus, refetchInterval: 10_000 })
  const env = useQuery({ queryKey: ["env-settings"], queryFn: api.envSettings })
  const zapSigner = useQuery({ queryKey: ["zap-signer"], queryFn: api.zapSignerStatus, refetchInterval: 10_000 })
  const saveMacaroon = useMutation({
    mutationFn: api.saveMacaroon,
    onSuccess: async () => {
      toast.success("Macaroon saved")
      setMacaroon("")
      setMacaroonOpen(false)
      setMacaroonError("")
      setActiveTab("env")
      await queryClient.invalidateQueries({ queryKey: ["auth-status"] })
    },
    onError: (error: Error) => setMacaroonError(error.message),
  })
  const saveEnv = useMutation({
    mutationFn: api.updateEnvSettings,
    onSuccess: async (result) => {
      toast.success(result.restart_required ? "Settings saved — restart lnSwitchboard to apply them" : "Settings saved")
      setDraftValues({})
      await queryClient.invalidateQueries({ queryKey: ["env-settings"] })
      await queryClient.invalidateQueries({ queryKey: ["summary"] })
    },
  })
  const generateZapSigner = useMutation({
    mutationFn: api.generateZapSigner,
    onSuccess: async () => {
      toast.success("Zap signer generated")
      setZapSignerError("")
      await queryClient.invalidateQueries({ queryKey: ["zap-signer"] })
    },
    onError: (error: Error) => setZapSignerError(error.message),
  })
  const importZapSigner = useMutation({
    mutationFn: api.importZapSigner,
    onSuccess: async () => {
      toast.success("Zap signer imported")
      setZapPrivateKey("")
      setZapSignerError("")
      await queryClient.invalidateQueries({ queryKey: ["zap-signer"] })
    },
    onError: (error: Error) => setZapSignerError(error.message),
  })
  const envSettings = useMemo(() => visibleEnvSettings(env.data?.settings ?? []), [env.data?.settings])
  const grouped = useMemo(() => groupSettings(envSettings), [envSettings])
  const dirtyValues = useMemo(() => {
    const values: Record<string, string> = {}
    for (const field of envSettings) {
      if (field.editable && draftValues[field.key] !== undefined && draftValues[field.key] !== field.value) {
        values[field.key] = draftValues[field.key]
      }
    }
    return values
  }, [draftValues, envSettings])
  const configured = auth.data?.configured === true
  const manualEntryAllowed = auth.data?.manual_entry_allowed !== false
  const preferredTab = preferredSettingsTab(auth.data)

  useEffect(() => {
    if (preferredTab === "env") {
      setActiveTab("env")
    }
  }, [preferredTab])

  return (
    <>
      <PageHeader
        eyebrow="Configuration"
        title="Settings"
        description="Rotate the invoice macaroon and edit safe environment settings."
      />
      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as SettingsTab)} className="flex flex-col gap-6">
        <div className="max-w-full overflow-x-auto overflow-y-hidden pb-2">
          <TabsList variant="line" className="h-11 w-max min-w-full justify-start gap-2 p-0">
            {settingsTabs.map((item) => (
              <TabsTrigger
                key={item.value}
                value={item.value}
                className="h-11 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent"
              >
                <item.icon />
                <span>{item.label}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="auth">
          <Card>
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2"><KeyRoundIcon /> Lightning macaroon</CardTitle>
                <CardDescription>{macaroonDescription(auth.data)}</CardDescription>
              </div>
              <Badge variant={configured ? "default" : "destructive"}>{macaroonStatusLabel(auth.data)}</Badge>
            </CardHeader>
            <CardContent>
              {!manualEntryAllowed ? (
                <div className="flex flex-col gap-3">
                  <div className="rounded-md border bg-muted/20 p-4 text-sm">
                    <div className="font-medium">Managed by LND_MACAROON_PATH</div>
                    <div className="mt-2 text-muted-foreground">
                      lnSwitchboard reads this mounted file directly and disables manual replacement to avoid writing over a packaged node secret.
                    </div>
                    {auth.data?.path ? (
                      <code className="mt-3 block break-all rounded-md bg-background px-3 py-2 font-mono text-xs text-foreground">
                        {auth.data.path}
                      </code>
                    ) : null}
                  </div>
                  {auth.data?.error ? <FieldError>{auth.data.error}</FieldError> : null}
                </div>
              ) : !configured || macaroonOpen ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault()
                    const value = macaroon.trim()
                    if (!value) {
                      setMacaroonError("Please paste a macaroon in hex.")
                      return
                    }
                    saveMacaroon.mutate(value)
                  }}
                >
                  <FieldGroup>
                    <Field data-invalid={Boolean(macaroonError)}>
                      <FieldLabel htmlFor="macaroon">Invoice macaroon</FieldLabel>
                      <div className="relative">
                        <Input id="macaroon" type={showMacaroon ? "text" : "password"} value={macaroon} onChange={(event) => setMacaroon(event.target.value)} aria-invalid={Boolean(macaroonError)} autoComplete="off" className="pr-10 font-mono" />
                        <Button type="button" variant="ghost" size="icon-sm" className="absolute top-1/2 right-1 -translate-y-1/2" onClick={() => setShowMacaroon((value) => !value)} aria-label={showMacaroon ? "Hide macaroon" : "Show macaroon"}>
                          {showMacaroon ? <EyeOffIcon /> : <EyeIcon />}
                        </Button>
                      </div>
                      <FieldDescription>Masked by default. Paste a hex-encoded invoice macaroon, or upload LND&apos;s binary invoice.macaroon below.</FieldDescription>
                      <FieldError>{macaroonError}</FieldError>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="macaroon-file">Binary macaroon file</FieldLabel>
                      <Input
                        id="macaroon-file"
                        type="file"
                        accept=".macaroon,application/octet-stream"
                        onChange={(event) => {
                          const file = event.target.files?.[0]
                          if (!file) return
                          void loadMacaroonFile(file, setMacaroon, setMacaroonError)
                        }}
                      />
                      <FieldDescription>Binary uploads are converted locally to hex before saving.</FieldDescription>
                    </Field>
                    <div className="flex justify-end gap-2">
                      {configured ? <Button type="button" variant="outline" onClick={() => setMacaroonOpen(false)}>Cancel</Button> : null}
                      <Button type="submit" disabled={saveMacaroon.isPending}>{saveMacaroon.isPending ? "Saving..." : "Save macaroon"}</Button>
                    </div>
                  </FieldGroup>
                </form>
              ) : (
                <Button type="button" variant="outline" onClick={() => setMacaroonOpen(true)}>Replace macaroon</Button>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="nostr">
          <Card>
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2"><RadioTowerIcon /> Nostr zap signer</CardTitle>
                <CardDescription>Signs NIP-57 zap receipts after linked Lightning invoices settle.</CardDescription>
              </div>
              <Badge variant={zapSigner.data?.configured ? "default" : "destructive"}>
                {zapSigner.data?.configured ? "Configured" : "Not configured"}
              </Badge>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              {zapSigner.isLoading ? <LoadingRows rows={1} /> : null}
              {zapSigner.isError ? <PageError message="Unable to load zap signer status." onRetry={() => void zapSigner.refetch()} retrying={zapSigner.isFetching} /> : null}
              {zapSigner.data ? (
                <div className="rounded-md border bg-muted/20 p-4 text-sm">
                  <div className="font-medium">Receipt public key</div>
                  <code className="mt-2 block break-all rounded-md bg-background px-3 py-2 font-mono text-xs text-foreground">
                    {zapSigner.data.pubkey || "No signer key generated"}
                  </code>
                  {zapSigner.data.path ? <p className="mt-2 text-xs text-muted-foreground">Stored at {zapSigner.data.path}</p> : null}
                  {zapSigner.data.pubkey ? <p className="mt-2 text-xs text-muted-foreground">Short key: {shortHash(zapSigner.data.pubkey, 12, 8)}</p> : null}
                  {zapSigner.data.error ? <FieldError>{zapSigner.data.error}</FieldError> : null}
                </div>
              ) : null}
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="zap-private-key">Import private key</FieldLabel>
                  <div className="relative">
                    <Input id="zap-private-key" type={showZapPrivateKey ? "text" : "password"} value={zapPrivateKey} onChange={(event) => setZapPrivateKey(event.target.value)} autoComplete="off" className="pr-10 font-mono" />
                    <Button type="button" variant="ghost" size="icon-sm" className="absolute top-1/2 right-1 -translate-y-1/2" onClick={() => setShowZapPrivateKey((value) => !value)} aria-label={showZapPrivateKey ? "Hide private key" : "Show private key"}>
                      {showZapPrivateKey ? <EyeOffIcon /> : <EyeIcon />}
                    </Button>
                  </div>
                  <FieldDescription>Masked by default. Paste a 32-byte hex Nostr private key; it is written locally and never returned by the API.</FieldDescription>
                </Field>
                <FieldError>{zapSignerError}</FieldError>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button type="button" variant="outline" disabled={generateZapSigner.isPending} onClick={() => generateZapSigner.mutate()}>
                    {generateZapSigner.isPending ? "Generating..." : zapSigner.data?.configured ? "Rotate signer" : "Generate signer"}
                  </Button>
                  <Button type="button" disabled={!zapPrivateKey.trim() || importZapSigner.isPending} onClick={() => importZapSigner.mutate(zapPrivateKey.trim())}>
                    {importZapSigner.isPending ? "Importing..." : "Import key"}
                  </Button>
                </div>
              </FieldGroup>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="env">
          <Card>
            <CardHeader className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2"><ServerCogIcon /> Environment settings</CardTitle>
                <CardDescription>Only backend-marked editable fields can be changed here.</CardDescription>
              </div>
              <Button disabled={Object.keys(dirtyValues).length === 0 || saveEnv.isPending} onClick={() => saveEnv.mutate(dirtyValues)}>
                <SaveIcon data-icon="inline-start" />
                {saveEnv.isPending ? "Saving..." : "Save changes"}
              </Button>
            </CardHeader>
            <CardContent className="flex flex-col gap-6">
              {env.isLoading ? <LoadingRows /> : null}
              {env.isError ? <PageError message="Unable to load environment settings." onRetry={() => void env.refetch()} retrying={env.isFetching} /> : null}
              {Object.entries(grouped).map(([category, fields]) => (
                <section key={category} className="flex flex-col gap-3">
                  <div>
                    <h2 className="text-lg font-semibold">{category}</h2>
                    <Separator className="mt-2" />
                  </div>
                  <div className="grid gap-4 lg:grid-cols-2">
                    {fields.map((field) => (
                      <EnvField
                        key={field.key}
                        field={field}
                        value={draftValues[field.key] ?? field.value ?? ""}
                        onChange={(value) => setDraftValues((current) => ({ ...current, [field.key]: value }))}
                      />
                    ))}
                  </div>
                </section>
              ))}
              {saveEnv.isError ? <FieldError>{saveEnv.error.message}</FieldError> : null}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}

export function macaroonStatusLabel(status?: AuthStatus): string {
  if (status?.manual_entry_allowed === false) return status.configured ? "Mounted file" : "File missing"
  return status?.configured ? "Manual secret" : "Not configured"
}

export function preferredSettingsTab(status?: AuthStatus): SettingsTab {
  return status?.configured ? "env" : "auth"
}

function macaroonDescription(status?: AuthStatus): string {
  if (status?.manual_entry_allowed === false) {
    return "Using LND's mounted invoice.macaroon directly. Manual replacement is disabled while LND_MACAROON_PATH is set."
  }
  return "Paste a hex invoice macaroon or upload LND's binary invoice.macaroon. It is stored locally as hex."
}

export async function loadMacaroonFile(
  file: File,
  setMacaroon: (value: string) => void,
  setError: (value: string) => void,
) {
  try {
    const bytes = new Uint8Array(await file.arrayBuffer())
    if (!bytes.length) {
      setError("Macaroon file cannot be empty.")
      return
    }
    setMacaroon(bytesToHex(bytes))
    setError("")
    toast.success("Binary macaroon loaded")
  } catch {
    setError("Unable to read macaroon file.")
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
}

function EnvField({
  field,
  value,
  onChange,
}: {
  field: EnvSetting
  value: string
  onChange: (value: string) => void
}) {
  const InputComponent = field.type === "textarea" ? Textarea : Input
  return (
    <Field data-disabled={!field.editable}>
      <FieldLabel htmlFor={`env-${field.key}`}>{field.label}</FieldLabel>
      <InputComponent
        id={`env-${field.key}`}
        type={field.type === "number" ? "number" : undefined}
        rows={field.type === "textarea" ? 4 : undefined}
        value={value}
        readOnly={!field.editable}
        disabled={!field.editable}
        onChange={(event) => onChange(event.target.value)}
      />
      <FieldDescription>
        {field.description}
        {field.hint_link?.href ? (
          <>
            {" "}
            <a href={field.hint_link.href}>{field.hint_link.label || "Open"}</a>.
          </>
        ) : null}
      </FieldDescription>
    </Field>
  )
}

export function visibleEnvSettings(settings: EnvSetting[]): EnvSetting[] {
  return settings.filter((field) => !hiddenEnvSettingKeys.has(field.key))
}

function groupSettings(settings: EnvSetting[]) {
  return settings.reduce<Record<string, EnvSetting[]>>((acc, field) => {
    const key = field.category || "General"
    acc[key] = [...(acc[key] || []), field]
    return acc
  }, {})
}
