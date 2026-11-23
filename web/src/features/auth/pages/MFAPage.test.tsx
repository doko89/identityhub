import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MFAPage } from "./MFAPage";

const realLocation = window.location;

beforeEach(() => {
  // MFAPage navigates via window.location on success; capture it.
  delete (window as unknown as { location?: Location }).location;
  window.location = { ...realLocation, href: "" } as Location;
});

afterEach(() => {
  cleanup();
  window.location = realLocation;
  vi.unstubAllGlobals();
});

describe("MFAPage verify", () => {
  it("submits the typed code from a single fillable input", async () => {
    let body: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        body = JSON.parse(String(init?.body)) as unknown;
        return new Response(null, { status: 204 });
      }),
    );
    const { getByLabelText, getByRole } = render(
      <MemoryRouter initialEntries={["/mfa?next=/apps"]}>
        <MFAPage />
      </MemoryRouter>,
    );
    const input = getByLabelText("6-digit code") as HTMLInputElement;
    // One plain field (not segmented slots) so password managers can fill it.
    expect(input.tagName).toBe("INPUT");
    expect(input.getAttribute("autocomplete")).toBe("one-time-code");
    // Focus lands in the code field immediately so the user can type.
    expect(document.activeElement).toBe(input);
    fireEvent.change(input, { target: { value: "123456" } });
    fireEvent.click(getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(body).toEqual({ code: "123456" }));
    expect(window.location.href).toBe("/apps");
  });
});

describe("MFAPage setup", () => {
  it("confirms enrollment from a single fillable input", async () => {
    let confirmBody: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        const u = url.toString();
        if (u.endsWith("/api/account/mfa/enroll")) {
          return Response.json({ otpauth_url: "otpauth://x", secret: "ABC", qr_png: "data:," });
        }
        confirmBody = JSON.parse(String(init?.body)) as unknown;
        return Response.json({ recovery_codes: ["r1"] });
      }),
    );
    const { getByLabelText, getByRole, getByText } = render(
      <MemoryRouter initialEntries={["/mfa?setup=1&next=/"]}>
        <MFAPage />
      </MemoryRouter>,
    );
    fireEvent.click(getByRole("button", { name: "Start setup" }));
    await waitFor(() => expect(getByLabelText("6-digit code")).toBeDefined());
    const input = getByLabelText("6-digit code") as HTMLInputElement;
    expect(input.tagName).toBe("INPUT");
    expect(input.getAttribute("autocomplete")).toBe("one-time-code");
    expect(document.activeElement).toBe(input);
    fireEvent.change(input, { target: { value: "654321" } });
    fireEvent.click(getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(confirmBody).toEqual({ code: "654321" }));
    await waitFor(() => expect(getByText("r1")).toBeDefined());
  });
});
