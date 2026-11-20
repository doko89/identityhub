import { ApiError } from "@/shared/api/client";

// Typed client for POST /api/uploads (TECH_SPEC §6.7). Any signed-in user
// may upload an avatar; app/SaaS logos are admin-only. The server
// re-encodes every image to webp and answers its public /uploads/... URL.

export type AssetType = "avatar" | "app_logo" | "saas_logo" | "login_background";

// MAX_UPLOAD_BYTES mirrors the backend's 10 MB input cap; the client
// rejects larger files before any byte leaves the browser.
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

export const ACCEPTED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"] as const;

export interface UploadResult {
  id: string;
  url: string;
  width: number;
  height: number;
  byte_size: number;
}

// validateImageFile mirrors the server rules (asset/service.go): non-empty,
// at most 10 MB, jpeg/png/webp. It returns the user-facing problem, if any.
export function validateImageFile(file: File): string | null {
  if (file.size === 0) {
    return "That file is empty. Choose an image to upload.";
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return "That image is larger than 10 MB. Choose a smaller file.";
  }
  if (!isAcceptedImage(file)) {
    return "That file is not a JPEG, PNG or WebP image.";
  }
  return null;
}

function isAcceptedImage(file: File): boolean {
  if ((ACCEPTED_IMAGE_TYPES as readonly string[]).includes(file.type)) {
    return true;
  }
  // Some browsers leave file.type empty; fall back to the extension.
  if (file.type === "") {
    return /\.(jpe?g|png|webp)$/i.test(file.name);
  }
  return false;
}

export async function uploadImage(assetType: AssetType, file: File): Promise<UploadResult> {
  const body = new FormData();
  body.set("asset_type", assetType);
  body.set("file", file);
  const res = await fetch("/api/uploads", { method: "POST", body });
  if (!res.ok) {
    const data = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(res.status, data?.error ?? `Upload failed (${res.status})`);
  }
  return (await res.json()) as UploadResult;
}
