import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";

// AuthSplitPanel is the wide brand panel of the auth split layout
// (DESIGN §5.1): the uploaded backdrop photo when one is set, else the
// built-in primary panel with the brand mark and tagline.
export function AuthSplitPanel() {
  const brand = useBrand();
  const orgName =
    brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const backgroundUrl =
    brand?.login_background_url !== undefined && brand.login_background_url !== ""
      ? brand.login_background_url
      : null;

  return (
    <div className="relative hidden overflow-hidden lg:col-span-3 lg:block">
      {backgroundUrl !== null ? (
        <>
          <img
            src={backgroundUrl}
            alt=""
            className="anim-fade absolute inset-0 h-full w-full object-cover"
          />
          <div
            aria-hidden="true"
            className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent"
          />
        </>
      ) : (
        <div aria-hidden="true" className="anim-fade absolute inset-0 bg-primary">
          <BrandMark className="absolute -right-10 -bottom-10 size-64 text-white/10" />
        </div>
      )}
      <div className="anim-rise absolute inset-x-0 bottom-0 p-10">
        <div className="flex items-center gap-3">
          {brand?.logo_url !== undefined && brand.logo_url !== "" ? (
            <img src={brand.logo_url} alt="" className="h-10" />
          ) : (
            <BrandMark className="size-10 text-white" />
          )}
          <p className="text-2xl font-bold text-white">{orgName}</p>
        </div>
        <p className="mt-3 max-w-md text-white/80">
          The single front door to every company app. Sign in once, open anything.
        </p>
      </div>
    </div>
  );
}
