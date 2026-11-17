import { useQuery } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { fetchBranding, type Branding } from "./api";
import { applyBrand, applyTheme } from "./apply";

const BrandContext = createContext<Branding | null>(null);

// useBrand returns the active brand, or null while it loads (pages fall
// back to the built-in defaults).
export function useBrand(): Branding | null {
  return useContext(BrandContext);
}

// BrandProvider fetches the brand once per minute and applies it.
// Failures keep the built-in defaults: branding must never break login.
export function BrandProvider({ children }: { children: ReactNode }) {
  const { data } = useQuery({
    queryKey: ["branding"],
    queryFn: fetchBranding,
    staleTime: 60_000,
    retry: 1,
  });
  const brand = useMemo(() => data ?? null, [data]);

  useEffect(() => {
    if (brand !== null) {
      applyBrand(brand);
    }
  }, [brand]);

  // System theme follows OS switches without a reload.
  useEffect(() => {
    if (brand === null || (brand.theme !== "" && brand.theme !== "system")) {
      return;
    }
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [brand]);

  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>;
}
