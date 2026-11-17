import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Wallpaper } from "./Wallpaper";

afterEach(() => {
  cleanup();
});

describe("Wallpaper", () => {
  it("renders sixteen rounded rectangles", () => {
    const { container } = render(<Wallpaper />);
    const rects = container.querySelectorAll("rect");
    expect(rects.length).toBe(16);
    for (const r of rects) {
      expect(r.getAttribute("fill")).toBe("currentColor");
      expect(Number(r.getAttribute("rx"))).toBeGreaterThan(0);
    }
  });

  it("stays behind content and out of the way", () => {
    const { container } = render(<Wallpaper />);
    const wrap = container.firstElementChild;
    expect(wrap?.getAttribute("aria-hidden")).toBe("true");
    expect(wrap?.className).toContain("pointer-events-none");
    expect(wrap?.className).toContain("fixed");
  });
});
