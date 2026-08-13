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
import { api, type Identity, type IdentityPayload } from "@/lib/api"
import { normalizeDomainInput, shortHash } from "@/lib/format"

type IdentityFormState = {
  local_part: string
  domain: string
  npub: string
  relays: string
}

const emptyForm: IdentityFormState = { local_part: "", domain: "", npub: "", relays: "" }
const RESERVED_LOCAL_PARTS = new Set(["nip-profile"])

export function IdentitiesPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState("")
  const [editing, setEditing] = useState<Identity | null>(null)
  const [deleting, setDeleting] = useState<Identity | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<IdentityFormState>(emptyForm)
  const [formError, setFormError] = useState("")
  const identities = useQuery({ queryKey: ["identities"], queryFn: api.identities })
  const save = useMutation({
    mutationFn: (payload: IdentityPayload) => editing ? api.updateIdentity(editing.id, payload) : api.createIdentity(payload),
    onSuccess: async () => {
      toast.success(editing ? "Mapping updated" : "Mapping created")
      setFormOpen(false)
      setEditing(null)
      await queryClient.invalidateQueries({ queryKey: ["identities"] })
    },
    onError: (error: Error) => setFormError(error.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteIdentity(id),
    onSuccess: async () => {
      toast.success("Mapping deleted")
      setDeleting(null)
      await queryClient.invalidateQueries({ queryKey: ["identities"] })
    },
  })
  const rows = useMemo(() => {
    const query = search.trim().toLowerCase()
    const items = [...(identities.data?.items ?? [])].sort(sortIdentity)
    if (!query) return items
    return items.filter((item) => [
      item.identifier,
      item.domain,
      item.npub,
      item.pubkey_hex,
      ...(item.relays || []),
    ].join(" ").toLowerCase().includes(query))
  }, [identities.data?.items, search])

  function openCreate() {
    setEditing(null)
    setForm(emptyForm)
    setFormError("")
    setFormOpen(true)
  }

  function openEdit(item: Identity) {
    setEditing(item)
    setForm({
      local_part: item.local_part,
      domain: item.domain,
      npub: item.npub || item.pubkey_hex,
      relays: (item.relays || []).join("\n"),
    })
    setFormError("")
    setFormOpen(true)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    const payload = collectIdentityPayload(form)
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
        title="Nostr Identities"
        action={(
          <>
            <div className="relative">
              <SearchIcon className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input aria-label="Search mappings" value={search} onChange={(event) => setSearch(event.target.value)} className="pl-8 sm:w-72" placeholder="Search mappings" />
            </div>
            <Button onClick={openCreate}><PlusIcon data-icon="inline-start" /> Add mapping</Button>
          </>
        )}
      />
      <div>
        {identities.isLoading ? <LoadingRows /> : null}
        {identities.isError ? <PageError message="Unable to load NIP-05 mappings." onRetry={() => void identities.refetch()} retrying={identities.isFetching} /> : null}
        {!identities.isLoading && !identities.isError && rows.length === 0 ? (
          <EmptyPanel title={search ? "No matching mappings" : "No mappings yet"} description="Create a mapping to publish a Nostr identity from this domain." />
        ) : null}
        {rows.length ? (
          <>
            <div className="hidden overflow-hidden rounded-md border lg:block">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Handle</TableHead>
                    <TableHead>Relays</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <span className="font-medium">{item.identifier}</span>
                          <code className="font-mono text-xs text-muted-foreground">{shortHash(item.npub, 16, 8)}</code>
                        </div>
                      </TableCell>
                      <TableCell><RelayList relays={item.relays} /></TableCell>
                      <TableCell className="text-right"><RowActions onEdit={() => openEdit(item)} onDelete={() => setDeleting(item)} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="grid gap-3 lg:hidden">
              {rows.map((item) => (
                <Card key={item.id}>
                  <CardHeader>
                    <CardTitle className="min-w-0 break-all text-base">{item.identifier}</CardTitle>
                    <CardDescription>{shortHash(item.npub, 18, 8)}</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3">
                    <RelayList relays={item.relays} />
                    <RowActions onEdit={() => openEdit(item)} onDelete={() => setDeleting(item)} />
                  </CardContent>
                </Card>
              ))}
            </div>
          </>
        ) : null}
      </div>
      <Dialog open={formOpen} onOpenChange={setFormOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{editing ? `Edit ${editing.identifier}` : "Add Nostr mapping"}</DialogTitle>
            <DialogDescription>Use an npub or a 64-character hex public key. Relay URLs can be newline or comma separated.</DialogDescription>
          </DialogHeader>
          <form onSubmit={submit}>
            <FieldGroup>
              <Field data-invalid={Boolean(formError)}>
                <FieldLabel htmlFor="identity-local">Local-part</FieldLabel>
                <Input id="identity-local" value={form.local_part} onChange={(event) => setForm({ ...form, local_part: event.target.value.toLowerCase() })} aria-invalid={Boolean(formError)} />
                <FieldDescription>Enter only the text before @.</FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="identity-domain">Domain</FieldLabel>
                <Input id="identity-domain" value={form.domain} onChange={(event) => setForm({ ...form, domain: event.target.value })} />
              </Field>
              <Field>
                <FieldLabel htmlFor="identity-npub">npub or hex key</FieldLabel>
                <Textarea id="identity-npub" value={form.npub} onChange={(event) => setForm({ ...form, npub: event.target.value })} rows={3} />
              </Field>
              <Field>
                <FieldLabel htmlFor="identity-relays">Relay URLs</FieldLabel>
                <Textarea id="identity-relays" value={form.relays} onChange={(event) => setForm({ ...form, relays: event.target.value })} rows={4} />
              </Field>
              <FieldError>{formError}</FieldError>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setFormOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={save.isPending}>{save.isPending ? "Saving..." : editing ? "Save changes" : "Create mapping"}</Button>
              </div>
            </FieldGroup>
          </form>
        </DialogContent>
      </Dialog>
      <AlertDialog open={Boolean(deleting)} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete mapping?</AlertDialogTitle>
            <AlertDialogDescription>{deleting ? `Delete ${deleting.identifier}? This removes the NIP-05 mapping from the well-known response.` : ""}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction disabled={!deleting || remove.isPending} onClick={() => deleting && remove.mutate(deleting.id)}>Delete mapping</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export function collectIdentityPayload(form: IdentityFormState): IdentityPayload | string {
  const localPart = form.local_part.trim().toLowerCase()
  const domain = normalizeDomainInput(form.domain)
  const npub = form.npub.trim()
  if (!localPart || !domain || !npub) return "Local-part, domain, and npub are required."
  if (RESERVED_LOCAL_PARTS.has(localPart)) return "That local-part is reserved."
  return {
    local_part: localPart,
    domain,
    npub,
    relays: form.relays.split(/[\r\n,]+/).map((relay) => relay.trim()).filter(Boolean),
  }
}

function sortIdentity(a: Identity, b: Identity) {
  return a.domain.localeCompare(b.domain) || a.local_part.localeCompare(b.local_part)
}

function RelayList({ relays }: { relays: string[] }) {
  const items = relays.filter(Boolean)
  if (!items.length) return <span className="text-sm text-muted-foreground">No relay hints</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((relay) => <Badge key={relay} variant="secondary" className="max-w-full min-w-0 truncate" title={relay}>{relay}</Badge>)}
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
