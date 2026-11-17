import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/shared/api/client";
import { uploadImage, validateImageFile } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

function png(size = 10): File {
  return new File([new Uint8Array(size)], "pic.png", { type: "image/png" });
}

describe("validateImageFile", () => {
  it("accepts jpeg, png and webp within 10 MB", () => {
    expect(validateImageFile(png())).toBeNull();
    expect(
      validateImageFile(new File([new Uint8Array(10)], "a.jpg", { type: "image/jpeg" })),
    ).toBeNull();
    expect(
      validateImageFile(new File([new Uint8Array(10)], "a.webp", { type: "image/webp" })),
    ).toBeNull();
  });

  it("rejects files larger than 10 MB", () => {
    const big = new File([new Uint8Array(10 * 1024 * 1024 + 1)], "big.png", { type: "image/png" });
    expect(validateImageFile(big)).toContain("10 MB");
  });

  it("rejects empty files", () => {
    expect(validateImageFile(new File([], "empty.png", { type: "image/png" }))).toContain("empty");
  });

  it("rejects non-image types", () => {
    expect(validateImageFile(new File([new Uint8Array(10)], "a.gif", { type: "image/gif" }))).toContain(
      "JPEG, PNG or WebP",
    );
  });
});

describe("uploadImage", () => {
  it("posts multipart fields and returns the result", async () => {
    const seen: Array<{ url: unknown; body: unknown }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        seen.push({ url, body: init?.body });
        expect(init?.method).toBe("POST");
        return Response.json(
          { id: "1", url: "/uploads/avatar/1.webp", width: 100, height: 80, byte_size: 10 },
          { status: 201 },
        );
      }),
    );
    const res = await uploadImage("avatar", png());
    expect(res.url).toBe("/uploads/avatar/1.webp");
    expect(seen[0]?.url).toBe("/api/uploads");
    const body = seen[0]?.body;
    expect(body).toBeInstanceOf(FormData);
    expect((body as FormData).get("asset_type")).toBe("avatar");
    expect(((body as FormData).get("file") as File).name).toBe("pic.png");
  });

  it("throws ApiError with the backend message on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "image must be jpeg, png or webp" }, { status: 400 })),
    );
    const err = await uploadImage("avatar", png()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(400);
    expect((err as ApiError).message).toContain("image must be jpeg, png or webp");
  });
});
