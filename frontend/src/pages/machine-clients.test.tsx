import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { vi } from "vitest"
import { MachineClients } from "./machine-clients"

afterEach(() => vi.unstubAllGlobals())

it("clears signing secrets immediately on a failed in-flight provision and prevents duplicate submits", async () => {
  const user = userEvent.setup()
  let finish!: (r: Response) => void
  let posts = 0
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (init?.method === "POST") { posts++; return new Promise<Response>(resolve => { finish = resolve }) }
    return new Response(JSON.stringify(input.endsWith("/status") ? { enabled: true, listening: false, host: "127.0.0.1", port: 22122, allow_private_webhooks: true } : { clients: [] }))
  }))
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={cache}><MachineClients /></QueryClientProvider>)
  await user.click(screen.getByRole("button", { name: "Add client" }))
  await user.type(screen.getByLabelText("Domain"), "pay.example.com")
  await user.type(screen.getByLabelText("Webhook URL"), "http://billing.example.com/bridge")
  await user.type(screen.getByLabelText("Webhook signing secret"), "synthetic-secret-to-clear-0000000000")
  await user.click(screen.getByRole("checkbox", { name: /Create addresses/ }))
  await user.dblClick(screen.getByRole("button", { name: "Provision client" }))
  expect(posts).toBe(1)
  expect(screen.getByLabelText("Webhook signing secret")).toHaveValue("")
  expect(screen.getByRole("button", { name: "Provisioning…" })).toBeDisabled()
  finish(new Response(JSON.stringify({ detail: "synthetic-secret-to-clear-0000000000" }), { status: 422 }))
  expect(await screen.findByRole("alert")).toHaveTextContent("outcome is unknown")
  expect(screen.queryByText("synthetic-secret-to-clear-0000000000")).not.toBeInTheDocument()
  expect(cache.getMutationCache().getAll()).toHaveLength(0)
})

it("does not imply revocation succeeded on error", async () => {
  const user = userEvent.setup()
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (init?.method === "DELETE") return new Response("{}", { status: 503 })
    return new Response(JSON.stringify(input.endsWith("/status") ? { enabled: true, listening: true, host: "0.0.0.0", port: 22122, allow_private_webhooks: false } : { clients: [{ client_id: "revoke-client", domain: "pay.example.com", scopes: ["addresses:create"], revoked: false }] }))
  }))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MachineClients /></QueryClientProvider>)
  await user.click(await screen.findByRole("button", { name: "Revoke" }))
  await user.click(screen.getByRole("button", { name: "Confirm revoke" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Revocation could not be confirmed")
  expect(screen.getByText("Active")).toBeInTheDocument()
  expect(screen.queryByText("Revoked")).not.toBeInTheDocument()
})

it("provisions with fixed routing and clears the one-time secret without query-cache persistence", async () => {
  const user = userEvent.setup()
  const token = "synthetic-one-time-value"
  const persist = vi.fn()
  vi.stubGlobal("localStorage", { setItem: persist, getItem: () => null })
  vi.stubGlobal("sessionStorage", { setItem: persist, getItem: () => null })
  const requests: RequestInit[] = []
  vi.stubGlobal("fetch", vi.fn(async (_input: string, init?: RequestInit) => {
    if (init?.method === "POST") { requests.push(init); return new Response(JSON.stringify({ client_id: "new-client", token, domain: "pay.example.com", scopes: ["addresses:create"] }), { status: 201 }) }
    return new Response(JSON.stringify(_input.endsWith("/status") ? { enabled: true, listening: true, host: "0.0.0.0", port: 22122, allow_private_webhooks: false } : { clients: [] }))
  }))
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(<QueryClientProvider client={cache}><MachineClients /></QueryClientProvider>)
  await user.click(screen.getByRole("button", { name: "Add client" }))
  await user.type(screen.getByLabelText("Domain"), "pay.example.com")
  await user.type(screen.getByLabelText("Webhook URL"), "https://billing.example.com/bridge")
  await user.type(screen.getByLabelText("Webhook signing secret"), "synthetic-signing-secret-000000000000")
  await user.click(screen.getByRole("checkbox", { name: /Create addresses/ }))
  await user.click(screen.getByRole("button", { name: "Provision client" }))
  expect(await screen.findByDisplayValue(token)).toBeInTheDocument()
  expect(requests).toHaveLength(1)
  expect(JSON.parse(requests[0].body as string)).toEqual({ domain: "pay.example.com", webhook_url: "https://billing.example.com/bridge", webhook_secret: "synthetic-signing-secret-000000000000", scopes: ["addresses:create"] })
  expect(screen.queryByDisplayValue("synthetic-signing-secret-000000000000")).not.toBeInTheDocument()
  expect(JSON.stringify(cache.getQueryCache().getAll().map(q => q.state))).not.toContain(token)
  expect(cache.getMutationCache().getAll()).toHaveLength(0)
  await user.click(screen.getByRole("button", { name: "Done — clear token" }))
  expect(screen.queryByDisplayValue(token)).not.toBeInTheDocument()
  view.unmount()
  render(<QueryClientProvider client={cache}><MachineClients /></QueryClientProvider>)
  expect(screen.queryByDisplayValue(token)).not.toBeInTheDocument()
  expect(persist).not.toHaveBeenCalled()
})

it("requires confirmation before revoking and refreshes authoritative state", async () => {
  const user = userEvent.setup()
  let revoked = false
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (init?.method === "DELETE") { revoked = true; return new Response(null, { status: 204 }) }
    return new Response(JSON.stringify(input.endsWith("/status") ? { enabled: true, listening: true, host: "0.0.0.0", port: 22122, allow_private_webhooks: false } : { clients: [{ client_id: "revoke-client", domain: "pay.example.com", scopes: ["addresses:create"], revoked }] }))
  }))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MachineClients /></QueryClientProvider>)
  await user.click(await screen.findByRole("button", { name: "Revoke" }))
  expect(revoked).toBe(false)
  expect(screen.getByText(/cannot cancel an accepted LND request/)).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Confirm revoke" }))
  await waitFor(() => expect(screen.getByText("Revoked")).toBeInTheDocument())
  expect(revoked).toBe(true)
})

it("refreshes a failed list without exposing response secrets", async () => {
  const user = userEvent.setup()
  let fail = true
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input.endsWith("/status")) return new Response("{}", { status: 503 })
    return fail ? new Response(JSON.stringify({ detail: "synthetic-do-not-reflect" }), { status: 500 }) : new Response(JSON.stringify({ clients: [] }))
  }))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MachineClients /></QueryClientProvider>)
  await screen.findByText("Couldn’t load clients. Refresh to try again.")
  expect(screen.queryByText(/synthetic-do-not-reflect/)).not.toBeInTheDocument()
  fail = false
  await user.click(screen.getByRole("button", { name: "Refresh clients" }))
  expect(await screen.findByText("No machine clients yet.")).toBeInTheDocument()
})

it("loads safe client metadata and explains the private endpoint", async () => {
  vi.stubGlobal("fetch", vi.fn(async (input: string) => new Response(JSON.stringify(input.endsWith("/status") ? { enabled: false, listening: false, host: "127.0.0.1", port: 22122, allow_private_webhooks: false } : { clients: [{ client_id: "synthetic-client", domain: "pay.example.com", scopes: ["addresses:create"], revoked: false }] }), { status: 200 })))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MachineClients /></QueryClientProvider>)
  expect(await screen.findByText("synthetic-client")).toBeInTheDocument()
  expect(screen.getByText(/Listener disabled/)).toBeInTheDocument()
  expect(screen.getByText(/Umbrel publishes client-only port 22122/)).toBeInTheDocument()
})
