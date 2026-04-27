import { useMemo, useState, type FormEvent } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { PencilIcon, PlusIcon, SearchIcon, Trash2Icon } from "lucide-react"
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
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
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
}

const emptyForm: AddressFormState = {
  local_part: "",
  domain: "",
  min_sats: "",
  max_sats: "",
  metadata_description: "",
  success_message: "",
  webhook_urls: "",
}

export function AddressesPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState("")
  const [editing, setEditing] = useState<LNAddress | null>(null)
  const [deleting, setDeleting] = useState<LNAddress | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<AddressFormState>(emptyForm)
  const [formError, setFormError] = useState("")
  const addresses = useQuery({ queryKey: ["addresses"], queryFn: api.addresses })
  const identities = useQuery({ queryKey: ["identities"], queryFn: api.identities })
  const save = useMutation({
    mutationFn: (payload: LNAddressPayload) => editing ? api.updateAddress(editing.id, payload) : api.createAddress(payload),
    onSuccess: async () => {
      toast.success(editing ? "LN address updated" : "LN address created")
      setFormOpen(false)
      setEditing(null)
      await queryClient.invalidateQueries({ queryKey: ["addresses"] })
    },
    onError: (error: Error) => setFormError(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAddress(id),
    onSuccess: async () => {
      toast.success("LN address deleted")
      setDeleting(null)
      await queryClient.invalidateQueries({ queryKey: ["addresses"] })
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

  function openEdit(item: LNAddress) {
    setEditing(item)
    setForm({
      local_part: item.local_part || "",
      domain: item.domain || "",
      min_sats: typeof item.min_sats === "number" ? String(item.min_sats) : "",
      max_sats: typeof item.max_sats === "number" ? String(item.max_sats) : "",
      metadata_description: item.metadata_description || "",
      success_message: item.success_message || "",
      webhook_urls: (item.webhook_urls || []).join("\n"),
    })
    setFormError("")
    setFormOpen(true)
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

  return (
    <>
      <PageHeader
        eyebrow="LNURL handles"
        title="LN Addresses"
        description="Create handle-specific min/max amounts, invoice templates, success messages, and webhook automation."
        action={<Button onClick={openCreate}><PlusIcon data-icon="inline-start" /> Add address</Button>}
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
          {addresses.isError ? <PageError message="Unable to load LN addresses." /> : null}
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
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.identifier}` : "Add LN address"}</DialogTitle>
            <DialogDescription>Configure only the base handle. Tags like user+vip inherit from the base local-part.</DialogDescription>
          </DialogHeader>
          <form onSubmit={submit}>
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
              <Field>
                <FieldLabel htmlFor="address-metadata">Metadata description</FieldLabel>
                <Textarea id="address-metadata" rows={3} value={form.metadata_description} onChange={(event) => setForm({ ...form, metadata_description: event.target.value })} placeholder="Inherits global default" />
              </Field>
              <Field>
                <FieldLabel htmlFor="address-success">Success message</FieldLabel>
                <Textarea id="address-success" rows={3} value={form.success_message} onChange={(event) => setForm({ ...form, success_message: event.target.value })} placeholder="Inherits global default" />
              </Field>
              <Field>
                <FieldLabel htmlFor="address-webhooks">Webhook URLs</FieldLabel>
                <Textarea id="address-webhooks" rows={4} value={form.webhook_urls} onChange={(event) => setForm({ ...form, webhook_urls: event.target.value })} placeholder="https://example.com/webhook" />
                <FieldDescription>One HTTP(S) endpoint per line. Duplicate URLs are ignored.</FieldDescription>
              </Field>
              <FieldError>{formError}</FieldError>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setFormOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving..." : editing ? "Save changes" : "Create override"}</Button>
              </div>
            </FieldGroup>
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
  const min = parseOptionalPositiveInt(form.min_sats, "Minimum sats")
  if (typeof min === "string") return min
  const max = parseOptionalPositiveInt(form.max_sats, "Maximum sats")
  if (typeof max === "string") return max
  if (min !== null && max !== null && max < min) return "Maximum sats must be greater than or equal to minimum sats."
  const webhooks: string[] = []
  for (const raw of form.webhook_urls.split(/[\r\n,]+/).map((value) => value.trim()).filter(Boolean)) {
    try {
      const parsed = new URL(raw)
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) return "Webhook URLs must start with http(s):// and include a host."
      const normalized = parsed.toString()
      if (!webhooks.includes(normalized)) webhooks.push(normalized)
    } catch {
      return "Each webhook URL must be a valid HTTP(S) address."
    }
  }
  return {
    local_part: localPart,
    domain,
    min_sats: min,
    max_sats: max,
    metadata_description: form.metadata_description.trim() || null,
    success_message: form.success_message.trim() || null,
    webhook_urls: webhooks,
  }
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

function AddressHandle({ item, hasIdentity }: { item: LNAddress; hasIdentity: boolean }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="font-medium">{item.identifier}</span>
      <div className="flex flex-wrap gap-1.5">
        {hasIdentity ? <Badge variant="secondary">Nostr identity linked</Badge> : null}
        {item.webhook_urls?.length ? <Badge variant="secondary">{item.webhook_urls.length === 1 ? "Webhook configured" : "Webhooks configured"}</Badge> : null}
      </div>
    </div>
  )
}

function Limits({ item }: { item: LNAddress }) {
  return (
    <div className="flex flex-col gap-1 text-sm">
      <span><span className="text-muted-foreground">Min:</span> {typeof item.min_sats === "number" ? `${formatNumber(item.min_sats)} sats` : "Global minimum"}</span>
      <span><span className="text-muted-foreground">Max:</span> {typeof item.max_sats === "number" ? `${formatNumber(item.max_sats)} sats` : "Channel max"}</span>
    </div>
  )
}

function Templates({ item }: { item: LNAddress }) {
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
