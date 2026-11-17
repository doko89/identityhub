// BrandMark is the built-in IdentityHub logo: a front doorway in a
// rounded square, drawn in the current text color so the branding
// primary re-themes it. Shown wherever no organization logo is
// uploaded (dashboard, auth pages, admin sidebar).
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" role="img" aria-label="IdentityHub logo" className={className}>
      <rect x="1" y="1" width="30" height="30" rx="8" fill="currentColor" />
      <path
        d="M12 25.5v-8.5a4 4 0 0 1 8 0v8.5a1.5 1.5 0 0 1-1.5 1.5h-5A1.5 1.5 0 0 1 12 25.5Z"
        fill="#fff"
      />
      <circle cx="17.6" cy="21.5" r="1.1" fill="currentColor" />
    </svg>
  );
}
