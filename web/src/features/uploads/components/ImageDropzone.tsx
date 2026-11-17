import { useRef, useState } from "react";
import { cn } from "cn";
import { Upload } from "lucide-react";
import { ApiError } from "@/shared/api/client";
import { ACCEPTED_IMAGE_TYPES, uploadImage, validateImageFile, type AssetType } from "../api";

// ImageDropzone turns its children into an image drop target: click (or
// Enter/Space) opens the file picker, or drop an image file onto it.
// Valid files upload via POST /api/uploads; onUploaded may be async
// (e.g. attach the URL to a profile) and its errors surface here too.
export function ImageDropzone({
  id,
  assetType,
  label,
  hint,
  onUploaded,
  className,
  children,
}: {
  id: string;
  assetType: AssetType;
  label: string;
  hint?: string;
  onUploaded: (url: string) => void | Promise<void>;
  className?: string;
  children: React.ReactNode;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const dragDepth = useRef(0);
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleFile(file: File | undefined) {
    if (file === undefined || busy) {
      return;
    }
    const problem = validateImageFile(file);
    if (problem !== null) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const uploaded = await uploadImage(assetType, file);
      await onUploaded(uploaded.url);
    } catch (err) {
      setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        aria-label={label}
        aria-busy={busy}
        data-dragover={dragOver}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragEnter={(e) => {
          e.preventDefault();
          dragDepth.current += 1;
          setDragOver(true);
        }}
        onDragOver={(e) => e.preventDefault()}
        onDragLeave={() => {
          dragDepth.current -= 1;
          if (dragDepth.current <= 0) {
            dragDepth.current = 0;
            setDragOver(false);
          }
        }}
        onDrop={(e) => {
          e.preventDefault();
          dragDepth.current = 0;
          setDragOver(false);
          void handleFile(e.dataTransfer.files?.[0]);
        }}
        className={cn(
          "relative inline-block cursor-pointer rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
          dragOver && "ring-2 ring-primary ring-offset-2",
          busy && "cursor-progress",
          className,
        )}
      >
        {children}
        {dragOver && !busy && (
          <div className="absolute inset-0 z-10 flex items-center justify-center rounded-[inherit] bg-background/80">
            <Upload className="size-5 text-primary" aria-hidden="true" />
            <span className="sr-only">Drop image to upload</span>
          </div>
        )}
        {busy && (
          <div className="absolute inset-0 z-10 flex items-center justify-center rounded-[inherit] bg-background/80">
            <span className="sr-only">Uploading…</span>
          </div>
        )}
      </div>
      <input
        ref={inputRef}
        id={id}
        type="file"
        accept={ACCEPTED_IMAGE_TYPES.join(",")}
        className="hidden"
        disabled={busy}
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          void handleFile(file);
        }}
        aria-label={label}
      />
      {hint !== undefined && error === null && !busy && (
        <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
      )}
      {error !== null && (
        <p role="alert" className="mt-1 text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}

function stripPrefix(message: string): string {
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}
