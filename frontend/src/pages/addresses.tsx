import { useMemo, useRef, useState, type FormEvent } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ForwardIcon, PencilIcon, PlusIcon, SearchIcon, Trash2Icon } from "lucide-react"
import { toast } from "sonner"

import { EmptyPanel, LoadingRows, PageError, PageHeader } from "@/components/common"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { api, type LNAddress, type LNAddressPayload } from "@/lib/api"
import { formatNumber, normalizeDomainInput } from "@/lib/format"

type AddressFormState = {
  local_part: string
  domain: string
  min_sats: string
  max_sats: string
  metadata_description: string
  success_message: string
  webhook_urls: string
  webhook_secret?: string
  webhook_tags?: string
  webhook_min_sats?: string
  webhook_max_sats?: string
  webhook_require_comment?: boolean
  webhook_payer_data_field?: string
  payer_data?: string
}

type ForwardingFormState = {
  local_part: string
  domain: string
  forward_to: string
  webhook_urls: string
  webhook_secret?: string
  webhook_tags?: string
  webhook_min_sats?: string
  webhook_max_sats?: string
  webhook_require_comment?: boolean
  webhook_payer_data_field?: string
}

export type ForwardingValidationState = {
  status: "idle" | "valid" | "invalid"
  target: string
  message: string
}

const emptyForm: AddressFormState = {
  local_part: "",
  domain: "",
  min_sats: "",
  max_sats: "",
  metadata_description: "",
  success_message: "",
  webhook_urls: "",
  webhook_secret: "",
  webhook_tags: "",
  webhook_min_sats: "",
  webhook_max_sats: "",
  webhook_require_comment: false,
  webhook_payer_data_field: "",
  payer_data: "",
}

const emptyForwardingForm: ForwardingFormState = {
  local_part: "",
  domain: "",
  forward_to: "",
  webhook_urls: "",
  webhook_secret: "",
  webhook_tags: "",
  webhook_min_sats: "",
  webhook_max_sats: "",
  webhook_require_comment: false,
  webhook_payer_data_field: "",
}

const emptyForwardingValidation: ForwardingValidationState = {
  status: "idle",
  target: "",
  message: "",
}
const RESERVED_LOCAL_PARTS = new Set(["nip-profile"])

export function AddressesPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState("")
  const [editing, setEditing] = useState<LNAddress | null>(null)
  const [deleting, setDeleting] = useState<LNAddress | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [forwardFormOpen, setForwardFormOpen] = useState(false)
  const [form, setForm] = useState<AddressFormState>(emptyForm)
  const [forwardForm, setForwardForm] = useState<ForwardingFormState>(emptyForwardingForm)
  const [formError, setFormError] = useState("")
  const [forwardFormError, setForwardFormError] = useState("")
  const [forwardValidation, setForwardValidation] = useState<ForwardingValidationState>(emptyForwardingValidation)
  const forwardToRef = useRef("")
  const addresses = useQuery({ queryKey: ["addresses"], queryFn: api.addresses })
  const identities = useQuery({ queryKey: ["identities"], queryFn: api.identities })
  const save = useMutation({
    mutationFn: (payload: LNAddressPayload) => editing ? api.updateAddress(editing.id, payload) : api.createAddress(payload),
    onSuccess: async () => {
      toast.success(editing ? "LN address updated" : "LN address created")
      setFormOpen(false)
      setForwardFormOpen(false)
      setEditing(null)
      await queryClient.invalidateQueries({ queryKey: ["addresses"] })
    },
    onError: (error: Error) => {
      if (forwardFormOpen) {
        setForwardFormError(error.message)
        return
      }
      setFormError(error.message)
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAddress(id),
    onSuccess: async () => {
      toast.success("LN address deleted")
      setDeleting(null)
      await queryClient.invalidateQueries({ queryKey: ["addresses"] })
    },
  })
  const validateForwarding = useMutation({
    mutationFn: (forwardTo: string) => api.validateForwardingAddress({ forward_to: forwardTo }),
    onSuccess: (result, forwardTo) => {
      if (normalizeForwardingInput(forwardToRef.current) !== normalizeForwardingInput(forwardTo)) return
      setForwardForm((current) => ({ ...current, forward_to: result.forward_to }))
      forwardToRef.current = result.forward_to
      setForwardValidation({ status: "valid", target: result.forward_to, message: `Validated ${result.forward_to}` })
      setForwardFormError("")
    },
    onError: (error: Error, forwardTo) => {
      if (normalizeForwardingInput(forwardToRef.current) !== normalizeForwardingInput(forwardTo)) return
      setForwardValidation({ status: "invalid", target: forwardTo, message: error.message })
      setForwardFormError(error.message)
    },
  })
  const identitySet = useMemo(() => new Set((identities.data?.items ?? []).map((item) => `${item.local_part}@${item.domain}`)), [identities.data?.items])
  const rows = useMemo(() => {
    const query = search.trim().toLowerCase()
    const items = [...(addresses.data?.items ?? [])].sort(sortAddress)
    if (!query) return items
    return items.filter((item) => [
      item.identifier,
      item.domain,
      item.metadata_description,
      item.success_message,
      ...(item.webhook_urls || []),
      item.payer_data ? Object.keys(item.payer_data).join(" ") : "",
      item.forward_to,
      item.min_sats,
      item.max_sats,
    ].join(" ").toLowerCase().includes(query))
  }, [addresses.data?.items, search])

  function openCreate() {
    setEditing(null)
    setForm(emptyForm)
    setFormError("")
    setFormOpen(true)
  }

  function openForwardCreate() {
    setEditing(null)
    setForwardForm(emptyForwardingForm)
    forwardToRef.current = ""
    setForwardValidation(emptyForwardingValidation)
    setForwardFormError("")
    setForwardFormOpen(true)
  }

  function openEdit(item: LNAddress) {
    if (item.routing_mode === "forward") {
      openForwardEdit(item)
      return
    }
    setEditing(item)
    setForm({
      local_part: item.local_part || "",
      domain: item.domain || "",
      min_sats: typeof item.min_sats === "number" ? String(item.min_sats) : "",
      max_sats: typeof item.max_sats === "number" ? String(item.max_sats) : "",
      metadata_description: item.metadata_description || "",
      success_message: item.success_message || "",
      webhook_urls: (item.webhook_urls || []).join("\n"),
      ...endpointFormFields(item),
      payer_data: formatPayerData(item.payer_data),
    })
    setFormError("")
    setFormOpen(true)
  }

  function openForwardEdit(item: LNAddress) {
    const forwardTo = item.forward_to || ""
    setEditing(item)
    setForwardForm({
      local_part: item.local_part || "",
      domain: item.domain || "",
      forward_to: forwardTo,
      webhook_urls: (item.webhook_urls || []).join("\n"),
      ...endpointFormFields(item),
    })
    forwardToRef.current = forwardTo
    setForwardValidation(
      forwardTo
        ? { status: "valid", target: forwardTo, message: `Validated ${forwardTo}` }
        : emptyForwardingValidation,
    )
    setForwardFormError("")
    setForwardFormOpen(true)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    const payload = collectAddressPayload(form)
    if (typeof payload === "string") {
      setFormError(payload)
      return
    }
    setFormError("")
    save.mutate(payload)
  }

  function submitForwarding(event: FormEvent) {
    event.preventDefault()
    const payload = collectForwardingAddressPayload(forwardForm, forwardValidation)
    if (typeof payload === "string") {
      setForwardFormError(payload)
      return
    }
    setForwardFormError("")
    save.mutate(payload)
  }

  function updateForwardTo(value: string) {
    forwardToRef.current = value
    setForwardForm({ ...forwardForm, forward_to: value })
    setForwardValidation(emptyForwardingValidation)
    setForwardFormError("")
  }

  function validateForwardTarget() {
    const target = forwardForm.forward_to.trim()
    if (!target) {
      setForwardFormError("Forwarding LN Address is required.")
      return
    }
    setForwardFormError("")
    validateForwarding.mutate(target)
  }

  const forwardTargetValidated = isForwardingValidationCurrent(forwardForm, forwardValidation)

  return (
    <>
      <PageHeader
        title="LN Addresses"
        action={(
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={openForwardCreate}><ForwardIcon data-icon="inline-start" /> Add forwarding address</Button>
            <Button onClick={openCreate}><PlusIcon data-icon="inline-start" /> Add address</Button>
          </div>
        )}
      />
      <Card>
        <CardHeader className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <CardTitle>Lightning Addresses</CardTitle>
            <CardDescription>{rows.length} address override{rows.length === 1 ? "" : "s"}</CardDescription>
          </div>
          <div className="relative">
            <SearchIcon className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={search} onChange={(event) => setSearch(event.target.value)} className="pl-8 sm:w-72" placeholder="Search addresses" />
          </div>
        </CardHeader>
        <CardContent>
          {addresses.isLoading ? <LoadingRows /> : null}
          {addresses.isError ? <PageError message="Unable to load LN addresses." onRetry={() => void addresses.refetch()} retrying={addresses.isFetching} /> : null}
          {!addresses.isLoading && !addresses.isError && rows.length === 0 ? (
            <EmptyPanel title={search ? "No matching addresses" : "No LN addresses yet"} description="Add a handle override to customize LNURL behavior for a local-part and domain." />
          ) : null}
          {rows.length ? (
            <>
              <div className="hidden overflow-hidden rounded-md border xl:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Handle</TableHead>
                      <TableHead>Limits</TableHead>
                      <TableHead>Templates</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((item) => (
                      <TableRow key={item.id}>
                        <TableCell><AddressHandle item={item} hasIdentity={identitySet.has(`${item.local_part}@${item.domain}`)} /></TableCell>
                        <TableCell><Limits item={item} /></TableCell>
                        <TableCell><Templates item={item} /></TableCell>
                        <TableCell className="text-right"><RowActions onEdit={() => openEdit(item)} onDelete={() => setDeleting(item)} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-3 xl:hidden">
                {rows.map((item) => (
                  <Card key={item.id}>
                    <CardHeader>
                      <CardTitle className="text-base"><AddressHandle item={item} hasIdentity={identitySet.has(`${item.local_part}@${item.domain}`)} /></CardTitle>
                    </CardHeader>
                    <CardContent className="flex flex-col gap-3">
                      <Limits item={item} />
                      <Templates item={item} />
                      <RowActions onEdit={() => openEdit(item)} onDelete={() => setDeleting(item)} />
                    </CardContent>
                  </Card>
                ))}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
      <Dialog open={formOpen} onOpenChange={setFormOpen}>
        <DialogContent className="max-h-[calc(100vh-2rem)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.identifier}` : "Add LN address"}</DialogTitle>
            <DialogDescription>Configure only the base handle. Tags like user+vip inherit from the base local-part.</DialogDescription>
          </DialogHeader>
          <form onSubmit={submit} className="flex min-h-0 flex-col gap-4">
            <Tabs defaultValue="handle" className="min-h-0">
              <div className="flex">
                <TabsList variant="line" className="h-10 w-fit justify-start gap-2 p-0">
                  <TabsTrigger value="handle" className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent">Handle</TabsTrigger>
                  <TabsTrigger value="lnurl" className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent">LNURL</TabsTrigger>
                  <TabsTrigger value="automation" className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent">Automation</TabsTrigger>
                </TabsList>
              </div>
              <TabsContent value="handle" className="max-h-[calc(100vh-17rem)] overflow-y-auto pt-4 pr-1">
                <FieldGroup>
                  <div className="grid gap-4 md:grid-cols-2">
                    <Field data-invalid={Boolean(formError)}>
                      <FieldLabel htmlFor="address-local">Local-part</FieldLabel>
                      <Input id="address-local" value={form.local_part} onChange={(event) => setForm({ ...form, local_part: event.target.value.toLowerCase() })} aria-invalid={Boolean(formError)} />
                      <FieldDescription>Do not include @ or +tags.</FieldDescription>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="address-domain">Domain</FieldLabel>
                      <Input id="address-domain" value={form.domain} onChange={(event) => setForm({ ...form, domain: event.target.value })} />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="address-min">Minimum sats</FieldLabel>
                      <Input id="address-min" type="number" min={1} value={form.min_sats} onChange={(event) => setForm({ ...form, min_sats: event.target.value })} placeholder="Global minimum" />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="address-max">Maximum sats</FieldLabel>
                      <Input id="address-max" type="number" min={1} value={form.max_sats} onChange={(event) => setForm({ ...form, max_sats: event.target.value })} placeholder="Channel max" />
                    </Field>
                  </div>
                </FieldGroup>
              </TabsContent>
              <TabsContent value="lnurl" className="max-h-[calc(100vh-17rem)] overflow-y-auto pt-4 pr-1">
                <FieldGroup>
                  <div className="grid gap-4 lg:grid-cols-2">
                    <Field>
                      <FieldLabel htmlFor="address-metadata">Metadata description</FieldLabel>
                      <Textarea id="address-metadata" rows={5} value={form.metadata_description} onChange={(event) => setForm({ ...form, metadata_description: event.target.value })} placeholder="Inherits global default" />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="address-success">Success message</FieldLabel>
                      <Textarea id="address-success" rows={5} value={form.success_message} onChange={(event) => setForm({ ...form, success_message: event.target.value })} placeholder="Inherits global default" />
                    </Field>
                  </div>
                  <Field>
                    <FieldLabel htmlFor="address-payer-data">Payer data fields</FieldLabel>
                    <Textarea id="address-payer-data" rows={4} value={form.payer_data} onChange={(event) => setForm({ ...form, payer_data: event.target.value })} placeholder='{"name": false, "identifier": true}' />
                    <FieldDescription>Optional LUD-18 schema for this handle. Use JSON or shorthand such as name,!identifier. The auth field is intentionally disabled.</FieldDescription>
                  </Field>
                </FieldGroup>
              </TabsContent>
              <TabsContent value="automation" className="max-h-[calc(100vh-17rem)] overflow-y-auto pt-4 pr-1">
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="address-webhooks">Webhook URLs</FieldLabel>
                    <Textarea id="address-webhooks" rows={4} value={form.webhook_urls} onChange={(event) => setForm({ ...form, webhook_urls: event.target.value })} placeholder="https://example.com/webhook" />
                    <FieldDescription>One HTTP(S) endpoint per line. Duplicate URLs are ignored.</FieldDescription>
                  </Field>
                  <WebhookAutomationFields
                    prefix="address"
                    secret={form.webhook_secret || ""}
                    tags={form.webhook_tags || ""}
                    minSats={form.webhook_min_sats || ""}
                    maxSats={form.webhook_max_sats || ""}
                    requireComment={Boolean(form.webhook_require_comment)}
                    payerDataField={form.webhook_payer_data_field || ""}
                    onChange={(updates) => setForm({ ...form, ...updates })}
                  />
                </FieldGroup>
              </TabsContent>
            </Tabs>
            <FieldError>{formError}</FieldError>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setFormOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving..." : editing ? "Save changes" : "Create override"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog open={forwardFormOpen} onOpenChange={setForwardFormOpen}>
        <DialogContent className="max-h-[calc(100vh-2rem)] grid-rows-[auto_minmax(0,1fr)] overflow-hidden sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.identifier}` : "Add forwarding address"}</DialogTitle>
            <DialogDescription>Map a local handle to a validated external Lightning Address.</DialogDescription>
          </DialogHeader>
          <form onSubmit={submitForwarding} className="flex min-h-0 flex-col gap-4">
            <Tabs defaultValue="route" className="min-h-0">
              <div className="flex">
                <TabsList variant="line" className="h-10 w-fit justify-start gap-2 p-0">
                  <TabsTrigger value="route" className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent">Route</TabsTrigger>
                  <TabsTrigger value="automation" className="h-10 flex-none rounded-none border-0 bg-transparent px-3 data-active:bg-transparent dark:data-active:bg-transparent">Automation</TabsTrigger>
                </TabsList>
              </div>
              <TabsContent value="route" className="max-h-[calc(100vh-17rem)] overflow-y-auto pt-4 pr-1">
                <FieldGroup>
                  <div className="grid gap-4 md:grid-cols-2">
                    <Field data-invalid={Boolean(forwardFormError)}>
                      <FieldLabel htmlFor="forward-local">Local-part</FieldLabel>
                      <Input id="forward-local" value={forwardForm.local_part} onChange={(event) => setForwardForm({ ...forwardForm, local_part: event.target.value.toLowerCase() })} aria-invalid={Boolean(forwardFormError)} />
                      <FieldDescription>Do not include @ or +tags.</FieldDescription>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="forward-domain">Domain</FieldLabel>
                      <Input id="forward-domain" value={forwardForm.domain} onChange={(event) => setForwardForm({ ...forwardForm, domain: event.target.value })} />
                    </Field>
                  </div>
                  <Field data-invalid={forwardValidation.status === "invalid"}>
                    <FieldLabel htmlFor="forward-target">Forward to LN Address</FieldLabel>
                    <div className="flex flex-col gap-2 sm:flex-row">
                      <Input id="forward-target" value={forwardForm.forward_to} onChange={(event) => updateForwardTo(event.target.value)} placeholder="username@domain.com" aria-invalid={forwardValidation.status === "invalid"} />
                      <Button type="button" variant="outline" onClick={validateForwardTarget} disabled={validateForwarding.isPending || !forwardForm.forward_to.trim()}>
                        {validateForwarding.isPending ? "Validating..." : "Validate"}
                      </Button>
                    </div>
                    <FieldDescription>{forwardValidation.status === "valid" ? forwardValidation.message : "The target must return a valid LNURL-pay payload before this address can be created."}</FieldDescription>
                  </Field>
                </FieldGroup>
              </TabsContent>
              <TabsContent value="automation" className="max-h-[calc(100vh-17rem)] overflow-y-auto pt-4 pr-1">
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="forward-webhooks">Webhook URLs</FieldLabel>
                    <Textarea id="forward-webhooks" rows={4} value={forwardForm.webhook_urls} onChange={(event) => setForwardForm({ ...forwardForm, webhook_urls: event.target.value })} placeholder="https://example.com/webhook" />
                    <FieldDescription>One HTTP(S) endpoint per line. Forwarded paid webhooks only fire when the target returns a usable verify URL.</FieldDescription>
                  </Field>
                  <WebhookAutomationFields
                    prefix="forward"
                    secret={forwardForm.webhook_secret || ""}
                    tags={forwardForm.webhook_tags || ""}
                    minSats={forwardForm.webhook_min_sats || ""}
                    maxSats={forwardForm.webhook_max_sats || ""}
                    requireComment={Boolean(forwardForm.webhook_require_comment)}
                    payerDataField={forwardForm.webhook_payer_data_field || ""}
                    onChange={(updates) => setForwardForm({ ...forwardForm, ...updates })}
                  />
                </FieldGroup>
              </TabsContent>
            </Tabs>
            <FieldError>{forwardFormError}</FieldError>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setForwardFormOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={save.isPending || !forwardTargetValidated}>{save.isPending ? "Saving..." : editing ? "Save changes" : "Create forwarding address"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <AlertDialog open={Boolean(deleting)} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete LN address?</AlertDialogTitle>
            <AlertDialogDescription>{deleting ? `Remove ${deleting.identifier}? This stops custom limits, templates, and webhook automation for that handle.` : ""}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction disabled={!deleting || remove.isPending} onClick={() => deleting && remove.mutate(deleting.id)}>Delete LN address</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export function collectAddressPayload(form: AddressFormState): LNAddressPayload | string {
  const localPart = form.local_part.trim().toLowerCase()
  const domain = normalizeDomainInput(form.domain)
  if (!localPart || !domain) return "Local-part and domain are required."
  if (RESERVED_LOCAL_PARTS.has(localPart)) return "That local-part is reserved."
  const min = parseOptionalPositiveInt(form.min_sats, "Minimum sats")
  if (typeof min === "string") return min
  const max = parseOptionalPositiveInt(form.max_sats, "Maximum sats")
  if (typeof max === "string") return max
  if (min !== null && max !== null && max < min) return "Maximum sats must be greater than or equal to minimum sats."
  const webhooks = collectWebhookUrls(form.webhook_urls)
  if (typeof webhooks === "string") return webhooks
  const webhookEndpoints = collectWebhookEndpoints(webhooks, form)
  if (typeof webhookEndpoints === "string") return webhookEndpoints
  const payerData = collectPayerData(form.payer_data || "")
  if (typeof payerData === "string") return payerData
  const payload: LNAddressPayload = {
    local_part: localPart,
    domain,
    min_sats: min,
    max_sats: max,
    metadata_description: form.metadata_description.trim() || null,
    success_message: form.success_message.trim() || null,
    webhook_urls: webhooks,
  }
  if (webhookEndpoints?.length) payload.webhook_endpoints = webhookEndpoints
  if (payerData !== null) payload.payer_data = payerData
  return payload
}

export function collectForwardingAddressPayload(form: ForwardingFormState, validation: ForwardingValidationState): LNAddressPayload | string {
  const localPart = form.local_part.trim().toLowerCase()
  const domain = normalizeDomainInput(form.domain)
  if (!localPart || !domain) return "Local-part and domain are required."
  if (RESERVED_LOCAL_PARTS.has(localPart)) return "That local-part is reserved."
  if (!form.forward_to.trim()) return "Forwarding LN Address is required."
  if (!isForwardingValidationCurrent(form, validation)) return "Validate the forwarding LN Address before creating this entry."
  const webhooks = collectWebhookUrls(form.webhook_urls)
  if (typeof webhooks === "string") return webhooks
  const webhookEndpoints = collectWebhookEndpoints(webhooks, form)
  if (typeof webhookEndpoints === "string") return webhookEndpoints
  const payload: LNAddressPayload = {
    local_part: localPart,
    domain,
    routing_mode: "forward",
    forward_to: validation.target,
    min_sats: null,
    max_sats: null,
    metadata_description: null,
    success_message: null,
    webhook_urls: webhooks,
  }
  if (webhookEndpoints?.length) payload.webhook_endpoints = webhookEndpoints
  return payload
}

function collectWebhookUrls(value: string): string[] | string {
  const webhooks: string[] = []
  for (const raw of value.split(/[\r\n,]+/).map((entry) => entry.trim()).filter(Boolean)) {
    try {
      const parsed = new URL(raw)
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) return "Webhook URLs must start with http(s):// and include a host."
      const normalized = parsed.toString()
      if (!webhooks.includes(normalized)) webhooks.push(normalized)
    } catch {
      return "Each webhook URL must be a valid HTTP(S) address."
    }
  }
  return webhooks
}

type WebhookAutomationState = Pick<
  AddressFormState,
  | "webhook_secret"
  | "webhook_tags"
  | "webhook_min_sats"
  | "webhook_max_sats"
  | "webhook_require_comment"
  | "webhook_payer_data_field"
>

function collectWebhookEndpoints(urls: string[], form: WebhookAutomationState): LNAddressPayload["webhook_endpoints"] | string {
  const min = parseOptionalPositiveInt(form.webhook_min_sats || "", "Webhook minimum sats")
  if (typeof min === "string") return min
  const max = parseOptionalPositiveInt(form.webhook_max_sats || "", "Webhook maximum sats")
  if (typeof max === "string") return max
  if (min !== null && max !== null && max < min) return "Webhook maximum sats must be greater than or equal to minimum sats."
  const tags = (form.webhook_tags || "").split(/[\r\n,]+/).map((tag) => tag.trim()).filter(Boolean)
  const hasAutomation =
    Boolean((form.webhook_secret || "").trim()) ||
    tags.length > 0 ||
    min !== null ||
    max !== null ||
    Boolean(form.webhook_require_comment) ||
    Boolean((form.webhook_payer_data_field || "").trim())
  if (!hasAutomation) return undefined
  const filters = {
    tags,
    min_msat: min === null ? null : min * 1000,
    max_msat: max === null ? null : max * 1000,
    require_comment: Boolean(form.webhook_require_comment),
    payer_data_field: (form.webhook_payer_data_field || "").trim() || null,
  }
  return urls.map((url) => ({
    url,
    label: "",
    secret: (form.webhook_secret || "").trim() || null,
    filters,
  }))
}

function collectPayerData(value: string): Record<string, boolean> | null | string {
  const trimmed = value.trim()
  if (!trimmed) return null
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "Payer data must be a JSON object."
    const result: Record<string, boolean> = {}
    for (const [key, mandatory] of Object.entries(parsed)) {
      const field = key.trim()
      if (!field) continue
      if (field.toLowerCase() === "auth") return "Payer data auth is not supported yet."
      result[field] = Boolean(mandatory)
    }
    return result
  } catch {
    const result: Record<string, boolean> = {}
    for (const part of trimmed.split(",")) {
      const raw = part.trim()
      if (!raw) continue
      const mandatory = raw.startsWith("!")
      const field = (mandatory ? raw.slice(1) : raw).trim()
      if (!field) continue
      if (field.toLowerCase() === "auth") return "Payer data auth is not supported yet."
      result[field] = mandatory
    }
    return Object.keys(result).length ? result : "Payer data must be JSON or comma-separated fields."
  }
}

export function isForwardingValidationCurrent(form: ForwardingFormState, validation: ForwardingValidationState): boolean {
  return validation.status === "valid" && normalizeForwardingInput(form.forward_to) === normalizeForwardingInput(validation.target)
}

function normalizeForwardingInput(value: string): string {
  return value.trim().toLowerCase()
}

function parseOptionalPositiveInt(value: string, label: string): number | null | string {
  if (!value.trim()) return null
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) return `${label} must be a positive number.`
  return Math.floor(parsed)
}

function sortAddress(a: LNAddress, b: LNAddress) {
  return a.domain.localeCompare(b.domain) || a.local_part.localeCompare(b.local_part)
}

function endpointFormFields(item: LNAddress): WebhookAutomationState {
  const endpoint = item.webhook_endpoints?.[0]
  const filters = endpoint?.filters ?? {}
  return {
    webhook_secret: "",
    webhook_tags: (filters.tags || []).join(","),
    webhook_min_sats: typeof filters.min_msat === "number" ? String(Math.floor(filters.min_msat / 1000)) : "",
    webhook_max_sats: typeof filters.max_msat === "number" ? String(Math.floor(filters.max_msat / 1000)) : "",
    webhook_require_comment: Boolean(filters.require_comment),
    webhook_payer_data_field: filters.payer_data_field || "",
  }
}

function formatPayerData(value?: Record<string, boolean>): string {
  if (!value || Object.keys(value).length === 0) return ""
  return JSON.stringify(value, null, 2)
}

function WebhookAutomationFields({
  prefix,
  secret,
  tags,
  minSats,
  maxSats,
  requireComment,
  payerDataField,
  onChange,
}: {
  prefix: string
  secret: string
  tags: string
  minSats: string
  maxSats: string
  requireComment: boolean
  payerDataField: string
  onChange: (updates: Partial<WebhookAutomationState>) => void
}) {
  return (
    <div className="grid gap-4 rounded-md border bg-muted/20 p-4 md:grid-cols-2">
      <Field>
        <FieldLabel htmlFor={`${prefix}-webhook-secret`}>Webhook signing secret</FieldLabel>
        <Input id={`${prefix}-webhook-secret`} type="password" autoComplete="off" value={secret} onChange={(event) => onChange({ webhook_secret: event.target.value })} placeholder="Leave blank for unsigned" />
        <FieldDescription>Masked by default. When set, deliveries include HMAC signature headers.</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`${prefix}-webhook-tags`}>Only +tags</FieldLabel>
        <Input id={`${prefix}-webhook-tags`} value={tags} onChange={(event) => onChange({ webhook_tags: event.target.value })} placeholder="vip,promo" />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${prefix}-webhook-min`}>Filter minimum sats</FieldLabel>
        <Input id={`${prefix}-webhook-min`} type="number" min={1} value={minSats} onChange={(event) => onChange({ webhook_min_sats: event.target.value })} />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${prefix}-webhook-max`}>Filter maximum sats</FieldLabel>
        <Input id={`${prefix}-webhook-max`} type="number" min={1} value={maxSats} onChange={(event) => onChange({ webhook_max_sats: event.target.value })} />
      </Field>
      <Field>
        <FieldLabel htmlFor={`${prefix}-webhook-payer-field`}>Required payer data field</FieldLabel>
        <Input id={`${prefix}-webhook-payer-field`} value={payerDataField} onChange={(event) => onChange({ webhook_payer_data_field: event.target.value })} placeholder="identifier" />
      </Field>
      <Field className="md:col-span-2">
        <label className="flex items-center gap-2 text-sm font-medium" htmlFor={`${prefix}-webhook-comment`}>
          <input
            id={`${prefix}-webhook-comment`}
            type="checkbox"
            checked={requireComment}
            onChange={(event) => onChange({ webhook_require_comment: event.target.checked })}
            className="size-4 rounded border-input"
          />
          Require payer comment before sending
        </label>
      </Field>
    </div>
  )
}

function AddressHandle({ item, hasIdentity }: { item: LNAddress; hasIdentity: boolean }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="font-medium">{item.identifier}</span>
      <div className="flex flex-wrap gap-1.5">
        {item.routing_mode === "forward" ? <Badge variant="outline">Forwarding</Badge> : null}
        {hasIdentity ? <Badge variant="secondary">Nostr identity linked</Badge> : null}
        {item.webhook_urls?.length ? <Badge variant="secondary">{item.webhook_urls.length === 1 ? "Webhook configured" : "Webhooks configured"}</Badge> : null}
      </div>
    </div>
  )
}

function Limits({ item }: { item: LNAddress }) {
  if (item.routing_mode === "forward") {
    return (
      <div className="flex flex-col gap-1 text-sm">
        <span><span className="text-muted-foreground">Min:</span> Target controlled</span>
        <span><span className="text-muted-foreground">Max:</span> Target controlled</span>
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-1 text-sm">
      <span><span className="text-muted-foreground">Min:</span> {typeof item.min_sats === "number" ? `${formatNumber(item.min_sats)} sats` : "Global minimum"}</span>
      <span><span className="text-muted-foreground">Max:</span> {typeof item.max_sats === "number" ? `${formatNumber(item.max_sats)} sats` : "Channel max"}</span>
    </div>
  )
}

function Templates({ item }: { item: LNAddress }) {
  if (item.routing_mode === "forward") {
    return (
      <div className="flex flex-col gap-1 text-sm">
        <span><span className="text-muted-foreground">Forwards to:</span> <span className="font-mono">{item.forward_to}</span></span>
        <span><span className="text-muted-foreground">Webhook settlement:</span> Remote verify when available</span>
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-1 text-sm">
      <span><span className="text-muted-foreground">Metadata:</span> {item.metadata_description || "Inherits global default"}</span>
      <span><span className="text-muted-foreground">Success:</span> {item.success_message || "Inherits global default"}</span>
    </div>
  )
}

function RowActions({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) {
  return (
    <div className="flex justify-end gap-2">
      <Button type="button" variant="outline" size="sm" onClick={onEdit}><PencilIcon data-icon="inline-start" /> Edit</Button>
      <Button type="button" variant="destructive" size="sm" onClick={onDelete}><Trash2Icon data-icon="inline-start" /> Delete</Button>
    </div>
  )
}
