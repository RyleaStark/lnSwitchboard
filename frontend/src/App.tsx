import { lazy, Suspense } from "react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { BrowserRouter, Navigate, Route, Routes } from "react-router"

import { AppShell } from "@/components/app-shell"
import { Spinner } from "@/components/ui/spinner"
import { Toaster } from "@/components/ui/sonner"

const AddressesPage = lazy(() => import("@/pages/addresses").then(({ AddressesPage }) => ({ default: AddressesPage })))
const DashboardPage = lazy(() => import("@/pages/dashboard").then(({ DashboardPage }) => ({ default: DashboardPage })))
const IdentitiesPage = lazy(() => import("@/pages/identities").then(({ IdentitiesPage }) => ({ default: IdentitiesPage })))
const InvoicesPage = lazy(() => import("@/pages/invoices").then(({ InvoicesPage }) => ({ default: InvoicesPage })))
const LiquidityPage = lazy(() => import("@/pages/liquidity").then(({ LiquidityPage }) => ({ default: LiquidityPage })))
const LogsPage = lazy(() => import("@/pages/logs").then(({ LogsPage }) => ({ default: LogsPage })))
const SettingsPage = lazy(() => import("@/pages/settings").then(({ SettingsPage }) => ({ default: SettingsPage })))
const WebhooksPage = lazy(() => import("@/pages/webhooks").then(({ WebhooksPage }) => ({ default: WebhooksPage })))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5_000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Suspense
          fallback={
            <div className="flex min-h-64 items-center justify-center" aria-live="polite">
              <Spinner className="size-6" />
            </div>
          }
        >
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<DashboardPage />} />
              <Route path="invoices/" element={<InvoicesPage />} />
              <Route path="liquidity/" element={<LiquidityPage />} />
              <Route path="logs/" element={<LogsPage />} />
              <Route path="addresses/" element={<AddressesPage />} />
              <Route path="identities/" element={<IdentitiesPage />} />
              <Route path="settings/" element={<SettingsPage />} />
              <Route path="webhooks/" element={<WebhooksPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </Suspense>
      </BrowserRouter>
      <Toaster position="top-right" richColors />
    </QueryClientProvider>
  )
}
