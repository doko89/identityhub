import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AccountMFAPage } from "@/features/account/pages/AccountMFAPage";
import { ConsentPage } from "@/features/auth/pages/ConsentPage";
import { LoginPage } from "@/features/auth/pages/LoginPage";
import { MFAPage } from "@/features/auth/pages/MFAPage";
import { DashboardPage } from "@/features/dashboard/pages/DashboardPage";

// App wires global providers (router, react-query). Routes: /login,
// /mfa + /account/mfa (M5), / dashboard (M6), /admin in M7.
export function App() {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/mfa" element={<MFAPage />} />
          <Route path="/consent" element={<ConsentPage />} />
          <Route path="/account/mfa" element={<AccountMFAPage />} />
          <Route path="/" element={<DashboardPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
