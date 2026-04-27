import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"

import { AppShell } from "@/components/app-shell"
import { Toaster } from "@/components/ui/sonner"
import { AddressesPage } from "@/pages/addresses"
import { DashboardPage } from "@/pages/dashboard"
import { IdentitiesPage } from "@/pages/identities"
import { InvoicesPage } from "@/pages/invoices"
import { LiquidityPage } from "@/pages/liquidity"
import { LogsPage } from "@/pages/logs"
import { SettingsPage } from "@/pages/settings"
import { WebhooksPage } from "@/pages/webhooks"

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
      </BrowserRouter>
      <Toaster position="top-right" richColors />
    </QueryClientProvider>
  )
}
