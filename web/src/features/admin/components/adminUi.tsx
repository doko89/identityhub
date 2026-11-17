import { Link } from "react-router-dom";
import { cn } from "cn";
import { ApiError } from "@/shared/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { ADMIN_PAGE_SIZE } from "../api";

// AdminNotice is the renderable form of a failed admin call: plain text,
// plus a step-up link when MFA verification can clear the 403.
export interface AdminNotice {
  text: string;
  stepUp: boolean;
}

// toNotice converts any failure into an AdminNotice: ApiError carries
// the backend's user-facing message, anything else is a network failure.
export function toNotice(err: unknown): AdminNotice {
  if (err instanceof ApiError) {
    return { text: err.mfaRequired ? `${stripPrefix(err.message)} ` : stripPrefix(err.message), stepUp: err.mfaRequired };
  }
  return { text: "Cannot reach the server. Try again.", stepUp: false };
}

function stripPrefix(message: string): string {
  // ApiError prefixes "API <status>: "; the notice shows the message only.
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}

// Notice renders an AdminNotice with the step-up link when relevant.
export function Notice({ value }: { value: AdminNotice | null }) {
  if (value === null) {
    return null;
  }
  return (
    <Alert variant="destructive" className="mb-4">
      <AlertTitle>Something went wrong</AlertTitle>
      <AlertDescription>
        {value.text}
        {value.stepUp && (
          <Link
            to={`/mfa?stepup=1&next=${encodeURIComponent(window.location.pathname)}`}
            className="font-medium underline underline-offset-4"
          >
            Verify with MFA to continue.
          </Link>
        )}
      </AlertDescription>
    </Alert>
  );
}

// Pager renders Prev/Next over a limit/offset list. Pass className to
// place it in a card footer; the default keeps the standalone spacing.
export function Pager({
  offset,
  total,
  onPage,
  className,
}: {
  offset: number;
  total: number;
  onPage: (offset: number) => void;
  className?: string;
}) {
  const page = Math.floor(offset / ADMIN_PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / ADMIN_PAGE_SIZE));
  return (
    <div className={cn("flex items-center gap-2 text-sm", className ?? "mt-3")}>
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={offset <= 0}
        onClick={() => onPage(Math.max(0, offset - ADMIN_PAGE_SIZE))}
      >
        ← Prev
      </Button>
      <span className="text-muted-foreground">
        Page {page} of {pages} ({total} total)
      </span>
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={offset + ADMIN_PAGE_SIZE >= total}
        onClick={() => onPage(offset + ADMIN_PAGE_SIZE)}
      >
        Next →
      </Button>
    </div>
  );
}
