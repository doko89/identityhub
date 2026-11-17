// Client-side text file download (no backend round trip).
export function formatRecoveryCodesFile(codes: string[]): string {
  return [
    "IdentityHub recovery codes",
    "Each code works once. Keep this file somewhere safe.",
    "",
    ...codes,
    "",
  ].join("\n");
}

export function downloadTextFile(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function downloadRecoveryCodes(codes: string[]): void {
  downloadTextFile("identityhub-recovery-codes.txt", formatRecoveryCodesFile(codes));
}
