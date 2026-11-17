import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ConsentPage } from "@/features/auth/pages/ConsentPage";
import { LoginPage } from "@/features/auth/pages/LoginPage";

// App wires global providers (router, react-query). Routes grow per
// milestone: /mfa + password pages in M1/M5, / dashboard in M6, /admin in M7.
export function App() {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/consent" element={<ConsentPage />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
