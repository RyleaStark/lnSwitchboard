import { useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { KeyRoundIcon, SaveIcon, ServerCogIcon } from "lucide-react"
import { toast } from "sonner"

import { CodeBlock, CopyButton, LoadingRows, PageError, PageHeader } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { api, type AuthStatus, type EnvSetting } from "@/lib/api"

export function SettingsPage() {
  const queryClient = useQueryClient()
  const [macaroon, setMacaroon] = useState("")
  const [macaroonOpen, setMacaroonOpen] = useState(false)
  const [macaroonError, setMacaroonError] = useState("")
  const [draftValues, setDraftValues] = useState<Record<string, string>>({})
  const auth = useQuery({ queryKey: ["auth-status"], queryFn: api.authStatus, refetchInterval: 10_000 })
  const env = useQuery({ queryKey: ["env-settings"], queryFn: api.envSettings })
  const saveMacaroon = useMutation({
    mutationFn: api.saveMacaroon,
    onSuccess: async () => {
      toast.success("Macaroon saved")
      setMacaroon("")
      setMacaroonOpen(false)
      setMacaroonError("")
      await queryClient.invalidateQueries({ queryKey: ["auth-status"] })
    },
    onError: (error: Error) => setMacaroonError(error.message),
  })
  const saveEnv = useMutation({
    mutationFn: api.updateEnvSettings,
    onSuccess: async () => {
      toast.success("Settings saved")
      setDraftValues({})
      await queryClient.invalidateQueries({ queryKey: ["env-settings"] })
      await queryClient.invalidateQueries({ queryKey: ["summary"] })
    },
  })
  const grouped = useMemo(() => groupSettings(env.data?.settings ?? []), [env.data?.settings])
  const dirtyValues = useMemo(() => {
    const values: Record<string, string> = {}
    for (const field of env.data?.settings ?? []) {
      if (field.editable && draftValues[field.key] !== undefined && draftValues[field.key] !== field.value) {
        values[field.key] = draftValues[field.key]
      }
    }
    return values
  }, [draftValues, env.data?.settings])
  const configured = auth.data?.configured === true
  const manualEntryAllowed = auth.data?.manual_entry_allowed !== false

  return (
    <>
      <PageHeader
        eyebrow="Configuration"
        title="Settings"
        description="Rotate the invoice macaroon, edit safe environment settings, and copy reverse-proxy routes for public LNURL and Nostr endpoints."
      />
      <Tabs defaultValue="auth" className="flex flex-col gap-5">
        <TabsList className="grid w-full grid-cols-3 md:w-fit">
          <TabsTrigger value="auth">Macaroon</TabsTrigger>
          <TabsTrigger value="env">Environment</TabsTrigger>
          <TabsTrigger value="proxy">Proxy</TabsTrigger>
        </TabsList>
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
                      <Textarea id="macaroon" rows={6} value={macaroon} onChange={(event) => setMacaroon(event.target.value)} aria-invalid={Boolean(macaroonError)} />
                      <FieldDescription>Paste a hex-encoded invoice macaroon, or upload LND's binary invoice.macaroon below.</FieldDescription>
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
              {env.isError ? <PageError message="Unable to load environment settings." /> : null}
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
        <TabsContent value="proxy">
          <ProxyCard />
        </TabsContent>
      </Tabs>
    </>
  )
}

export function macaroonStatusLabel(status?: AuthStatus): string {
  if (status?.manual_entry_allowed === false) return status.configured ? "Mounted file" : "File missing"
  return status?.configured ? "Manual secret" : "Not configured"
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

function ProxyCard() {
  const host = window.location.host || "your-domain.example"
  const nginx = `location /.well-known/lnurlp/ {\n  proxy_pass http://127.0.0.1:22121;\n  proxy_set_header Host $host;\n  proxy_set_header X-Forwarded-Proto $scheme;\n  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n}\n\nlocation = /.well-known/nostr.json {\n  proxy_pass http://127.0.0.1:22121;\n  proxy_set_header Host $host;\n  proxy_set_header X-Forwarded-Proto $scheme;\n}`
  const caddy = `${host} {\n  reverse_proxy /.well-known/lnurlp/* 127.0.0.1:22121\n  reverse_proxy /.well-known/nostr.json 127.0.0.1:22121\n}`
  return (
    <Card>
      <CardHeader>
        <CardTitle>Serve LNURL + Nostr from your domain</CardTitle>
        <CardDescription>Expose only well-known public endpoints to wallets. Keep the operator UI private.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
          Public routes: <code className="font-mono">/.well-known/lnurlp/*</code> and <code className="font-mono">/.well-known/nostr.json</code>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button variant="outline">Show proxy snippets</Button>
          </DialogTrigger>
          <DialogContent className="min-w-0 max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-3xl">
            <DialogHeader>
              <DialogTitle>Proxy snippets</DialogTitle>
              <DialogDescription>Copy the block that matches your reverse proxy and adjust the upstream if your service port differs.</DialogDescription>
            </DialogHeader>
            <div className="flex min-w-0 flex-col gap-4">
              <Snippet title="Nginx" value={nginx} />
              <Snippet title="Caddy" value={caddy} />
            </div>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  )
}

function Snippet({ title, value }: { title: string; value: string }) {
  return (
    <section className="flex min-w-0 flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-medium">{title}</h3>
        <CopyButton value={value} label="Copy" copiedLabel={`${title} snippet copied`} />
      </div>
      <CodeBlock>{value}</CodeBlock>
    </section>
  )
}

function groupSettings(settings: EnvSetting[]) {
  return settings.reduce<Record<string, EnvSetting[]>>((acc, field) => {
    const key = field.category || "General"
    acc[key] = [...(acc[key] || []), field]
    return acc
  }, {})
}
