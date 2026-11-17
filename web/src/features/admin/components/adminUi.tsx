import { Link } from "react-router-dom";
import { ApiError } from "@/shared/api/client";
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
    <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
      {value.text}
      {value.stepUp && (
        <Link
          to={`/mfa?stepup=1&next=${encodeURIComponent(window.location.pathname)}`}
          style={{ color: "var(--primary)" }}
        >
          Verify with MFA to continue.
        </Link>
      )}
    </p>
  );
}

// Pager renders Prev/Next over a limit/offset list.
export function Pager({
  offset,
  total,
  onPage,
}: {
  offset: number;
  total: number;
  onPage: (offset: number) => void;
}) {
  const page = Math.floor(offset / ADMIN_PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / ADMIN_PAGE_SIZE));
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 12, fontSize: 13 }}>
      <button
        type="button"
        style={pagerButtonStyle}
        disabled={offset <= 0}
        onClick={() => onPage(Math.max(0, offset - ADMIN_PAGE_SIZE))}
      >
        ← Prev
      </button>
      <span style={{ color: "var(--muted-foreground)" }}>
        Page {page} of {pages} ({total} total)
      </span>
      <button
        type="button"
        style={pagerButtonStyle}
        disabled={offset + ADMIN_PAGE_SIZE >= total}
        onClick={() => onPage(offset + ADMIN_PAGE_SIZE)}
      >
        Next →
      </button>
    </div>
  );
}

const pagerButtonStyle: React.CSSProperties = {
  padding: "6px 12px",
  border: "1px solid var(--border)",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "transparent",
  color: "var(--foreground)",
  fontSize: 13,
  cursor: "pointer",
};
