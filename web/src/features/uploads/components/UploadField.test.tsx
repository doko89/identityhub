import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UploadField } from "./UploadField";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const result = { id: "1", url: "/uploads/avatar/1.webp", width: 100, height: 80, byte_size: 10 };

function png(name = "pic.png", size = 10): File {
  return new File([new Uint8Array(size)], name, { type: "image/png" });
}

function pickFile(container: HTMLElement, file: File) {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files: [file] } });
}

describe("UploadField", () => {
  it("uploads a valid file and shows the result", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const onUploaded = vi.fn();
    const { container, getByText } = render(
      <UploadField id="u" assetType="avatar" label="Avatar" onUploaded={onUploaded} />,
    );
    pickFile(container, png());
    await waitFor(() => expect(getByText(/\/uploads\/avatar\/1\.webp/)).toBeDefined());
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(onUploaded).toHaveBeenCalledWith("/uploads/avatar/1.webp");
    const img = container.querySelector('img[src="/uploads/avatar/1.webp"]');
    expect(img).not.toBeNull();
  });

  it("rejects oversize files without calling the API", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole } = render(
      <UploadField id="u" assetType="avatar" label="Avatar" />,
    );
    pickFile(container, png("big.png", 10 * 1024 * 1024 + 1));
    await waitFor(() => expect(getByRole("alert")).toBeDefined());
    expect(getByRole("alert").textContent).toContain("10 MB");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects non-image files without calling the API", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole } = render(
      <UploadField id="u" assetType="avatar" label="Avatar" />,
    );
    pickFile(container, new File([new Uint8Array(10)], "a.gif", { type: "image/gif" }));
    await waitFor(() => expect(getByRole("alert")).toBeDefined());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the backend message when the upload fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "image exceeds 10 MB" }, { status: 400 })),
    );
    const { container, getByRole } = render(
      <UploadField id="u" assetType="avatar" label="Avatar" />,
    );
    pickFile(container, png());
    await waitFor(() => expect(getByRole("alert").textContent).toContain("image exceeds 10 MB"));
  });
});
