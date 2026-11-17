import { useBrand } from "@/features/branding/BrandProvider";

// AuthBrandHeader renders the organization logo + name centered above
// the auth card (DESIGN: brand lives outside the card). It falls back
// to the built-in name while the brand loads or when none is set.
export function AuthBrandHeader() {
  const brand = useBrand();
  const orgName =
    brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  return (
    <div className="flex flex-col items-center gap-2 text-center">
      {brand?.logo_url !== undefined && brand.logo_url !== "" && (
        <img src={brand.logo_url} alt="" className="h-9" />
      )}
      <h1 className="text-xl font-semibold">{orgName}</h1>
    </div>
  );
}
