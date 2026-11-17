import { useQuery } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { fetchBranding, type Branding } from "./api";
import { applyBrand, applyTheme, resolveTheme } from "./apply";

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

  // The stored user choice (or the OS default) applies even when the
  // brand endpoint fails: branding must never break the theme.
  useEffect(() => {
    if (brand !== null) {
      applyBrand(brand);
    } else {
      applyTheme(resolveTheme(""));
    }
  }, [brand]);

  // System theme follows OS switches without a reload. The listener is
  // active only while the winning choice is "system" (a stored explicit
  // mode wins over brand and OS alike).
  const brandTheme = brand?.theme ?? "";
  useEffect(() => {
    if (resolveTheme(brandTheme) !== "system") {
      return;
    }
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme(resolveTheme(brandTheme));
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [brandTheme]);

  return <BrandContext.Provider value={brand}>{children}</BrandContext.Provider>;
}
