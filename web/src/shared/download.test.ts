import { afterEach, describe, expect, it, vi } from "vitest";
import { downloadRecoveryCodes, formatRecoveryCodesFile } from "./download";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("formatRecoveryCodesFile", () => {
  it("lists every code under a header", () => {
    const text = formatRecoveryCodesFile(["AAAA-1111", "BBBB-2222"]);
    expect(text).toContain("IdentityHub recovery codes");
    expect(text).toContain("AAAA-1111");
    expect(text).toContain("BBBB-2222");
    expect(text.indexOf("AAAA-1111")).toBeLessThan(text.indexOf("BBBB-2222"));
  });
});

describe("downloadRecoveryCodes", () => {
  it("triggers an anchor download of a file carrying the codes", async () => {
    const seen: Blob[] = [];
    const create = vi.fn((blob: Blob) => {
      seen.push(blob);
      return "blob:fake";
    });
    const revoke = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: create, revokeObjectURL: revoke });
    const append = vi.spyOn(document.body, "appendChild");
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    downloadRecoveryCodes(["AAAA-1111"]);

    expect(create).toHaveBeenCalledOnce();
    expect(append).toHaveBeenCalledOnce();
    const node = append.mock.calls[0]?.[0];
    expect(node).toBeInstanceOf(HTMLAnchorElement);
    const anchor = node as HTMLAnchorElement;
    expect(anchor.download).toBe("identityhub-recovery-codes.txt");
    expect(anchor.href).toBe("blob:fake");
    expect(revoke).toHaveBeenCalledWith("blob:fake");
    expect(seen).toHaveLength(1);
    await expect(seen[0]?.text()).resolves.toContain("AAAA-1111");
  });
});
