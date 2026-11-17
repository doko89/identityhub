import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/shared/api/client";
import { ImageDropzone } from "./ImageDropzone";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const result = { id: "1", url: "/uploads/avatar/1.webp", width: 100, height: 80, byte_size: 10 };

function png(name = "pic.png", size = 10): File {
  return new File([new Uint8Array(size)], name, { type: "image/png" });
}

function renderZone(onUploaded: (url: string) => void | Promise<void> = () => {}) {
  return render(
    <ImageDropzone id="dz" assetType="avatar" label="Change picture" onUploaded={onUploaded}>
      <span>preview</span>
    </ImageDropzone>,
  );
}

function dropFile(container: HTMLElement, file: File) {
  const zone = container.querySelector('[role="button"]') as HTMLElement;
  fireEvent.drop(zone, { dataTransfer: { files: [file] } });
}

function pickFile(container: HTMLElement, file: File) {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files: [file] } });
}

describe("ImageDropzone", () => {
  it("uploads a dropped file and reports its URL", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const onUploaded = vi.fn();
    const { container } = renderZone(onUploaded);
    dropFile(container, png());
    await waitFor(() => expect(onUploaded).toHaveBeenCalledWith("/uploads/avatar/1.webp"));
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("uploads a picked file", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const onUploaded = vi.fn();
    const { container } = renderZone(onUploaded);
    pickFile(container, png());
    await waitFor(() => expect(onUploaded).toHaveBeenCalledWith("/uploads/avatar/1.webp"));
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects oversize files without calling the API", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole } = renderZone();
    dropFile(container, png("big.png", 10 * 1024 * 1024 + 1));
    await waitFor(() => expect(getByRole("alert")).toBeDefined());
    expect(getByRole("alert").textContent).toContain("10 MB");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects non-image files without calling the API", async () => {
    const fetchMock = vi.fn(async () => Response.json(result, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole } = renderZone();
    dropFile(container, new File([new Uint8Array(10)], "a.gif", { type: "image/gif" }));
    await waitFor(() => expect(getByRole("alert")).toBeDefined());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the backend message when the upload fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "image exceeds 10 MB" }, { status: 400 })),
    );
    const { container, getByRole } = renderZone();
    dropFile(container, png());
    await waitFor(() => expect(getByRole("alert").textContent).toContain("image exceeds 10 MB"));
  });

  it("surfaces async onUploaded rejections", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json(result, { status: 201 })));
    const onUploaded = vi.fn(async () => {
      throw new ApiError(400, "avatar_url must be an /uploads/ image URL");
    });
    const { container, getByRole } = renderZone(onUploaded);
    dropFile(container, png());
    await waitFor(() => expect(getByRole("alert").textContent).toContain("avatar_url must be"));
  });

  it("shows a drop hint while dragging and hides it on leave", () => {
    const { container, queryByText } = renderZone();
    const zone = container.querySelector('[role="button"]') as HTMLElement;
    fireEvent.dragEnter(zone);
    expect(zone.getAttribute("data-dragover")).toBe("true");
    expect(queryByText("Drop image to upload")).not.toBeNull();
    fireEvent.dragLeave(zone);
    expect(zone.getAttribute("data-dragover")).toBe("false");
    expect(queryByText("Drop image to upload")).toBeNull();
  });

  it("marks the surface busy while uploading", async () => {
    let resolve: ((v: Response) => void) | undefined;
    const gate = new Promise<Response>((r) => {
      resolve = r;
    });
    vi.stubGlobal("fetch", vi.fn(() => gate));
    const { container, queryByText } = renderZone();
    const zone = container.querySelector('[role="button"]') as HTMLElement;
    dropFile(container, png());
    await waitFor(() => expect(zone.getAttribute("aria-busy")).toBe("true"));
    expect(queryByText("Uploading…")).not.toBeNull();
    resolve?.(Response.json(result, { status: 201 }));
    await waitFor(() => expect(zone.getAttribute("aria-busy")).toBe("false"));
  });

  it("opens the picker on Enter", () => {
    const { container } = renderZone();
    const zone = container.querySelector('[role="button"]') as HTMLElement;
    const click = vi.spyOn(HTMLInputElement.prototype, "click").mockImplementation(() => {});
    fireEvent.keyDown(zone, { key: "Enter" });
    expect(click).toHaveBeenCalledOnce();
  });
});
