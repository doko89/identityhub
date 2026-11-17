import { useState } from "react";
import { ApiError } from "@/shared/api/client";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { ACCEPTED_IMAGE_TYPES, uploadImage, validateImageFile, type AssetType } from "../api";

// UploadField picks one image file, posts it to /api/uploads, and shows
// the result (thumbnail + URL + dimensions). Parent pages take the URL
// via onUploaded — the account page shows it, the branding editor fills
// its URL fields with it.
export function UploadField({
  id,
  assetType,
  label,
  description,
  initialUrl,
  onUploaded,
}: {
  id: string;
  assetType: AssetType;
  label: string;
  description?: string;
  initialUrl?: string;
  onUploaded?: (url: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ url: string; width: number; height: number } | null>(null);

  async function onChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const problem = validateImageFile(file);
    if (problem !== null) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const uploaded = await uploadImage(assetType, file);
      setResult({ url: uploaded.url, width: uploaded.width, height: uploaded.height });
      onUploaded?.(uploaded.url);
    } catch (err) {
      setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const preview = result?.url ?? (initialUrl !== undefined && initialUrl !== "" ? initialUrl : null);

  return (
    <Field data-invalid={error !== null}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <div className="flex items-center gap-3">
        {preview !== null && (
          <img
            src={preview}
            alt=""
            className="size-10 rounded-md border object-cover"
          />
        )}
        <Input
          id={id}
          type="file"
          accept={ACCEPTED_IMAGE_TYPES.join(",")}
          disabled={busy}
          onChange={(e) => void onChange(e)}
          aria-describedby={description !== undefined ? `${id}-description` : undefined}
        />
      </div>
      {description !== undefined && <FieldDescription id={`${id}-description`}>{description}</FieldDescription>}
      {busy && <p className="text-sm text-muted-foreground">Uploading…</p>}
      {error !== null && <FieldError>{error}</FieldError>}
      {result !== null && (
        <p className="text-sm text-muted-foreground">
          Uploaded <code className="font-mono text-xs">{result.url}</code> ({result.width}×
          {result.height}).
        </p>
      )}
    </Field>
  );
}

function stripPrefix(message: string): string {
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}
