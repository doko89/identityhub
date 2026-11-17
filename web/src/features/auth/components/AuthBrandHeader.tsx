import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";

// AuthBrandHeader renders the organization logo + name centered above
// the auth card (DESIGN: brand lives outside the card). Without an
// uploaded logo it shows the built-in mark and the default name.
export function AuthBrandHeader() {
  const brand = useBrand();
  const orgName =
    brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  return (
    <div className="flex flex-col items-center gap-2 text-center">
      {brand?.logo_url !== undefined && brand.logo_url !== "" ? (
        <img src={brand.logo_url} alt="" className="h-9" />
      ) : (
        <BrandMark className="size-10 text-primary" />
      )}
      <h1 className="text-xl font-semibold">{orgName}</h1>
    </div>
  );
}
