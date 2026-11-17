import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Wallpaper, WallpaperPicker } from "./Wallpaper";
import { loadWallpaper, WALLPAPER_STORAGE_KEY } from "./wallpaper";

afterEach(() => {
  cleanup();
  localStorage.clear();
});

describe("Wallpaper", () => {
  it("renders nothing for plain", () => {
    const { container } = render(<Wallpaper choice="plain" />);
    expect(container.querySelector("svg")).toBeNull();
  });

  it("renders seeded shapes per choice", () => {
    const rects = render(<Wallpaper choice="rects" />);
    expect(rects.container.querySelectorAll("rect").length).toBe(16);
    const dots = render(<Wallpaper choice="dots" />);
    expect(dots.container.querySelectorAll("circle").length).toBe(14 * 9);
    const rings = render(<Wallpaper choice="rings" />);
    const circles = rings.container.querySelectorAll("circle");
    expect(circles.length).toBe(12);
    expect(circles[0]?.getAttribute("fill")).toBe("none");
    expect(circles[0]?.getAttribute("stroke")).toBe("currentColor");
  });

  it("is deterministic per choice", () => {
    const a = render(<Wallpaper choice="rects" />);
    const b = render(<Wallpaper choice="rects" />);
    expect(a.container.innerHTML).toBe(b.container.innerHTML);
  });

  it("loads the stored choice with a safe default", () => {
    expect(loadWallpaper()).toBe("rects");
    localStorage.setItem(WALLPAPER_STORAGE_KEY, "dots");
    expect(loadWallpaper()).toBe("dots");
    localStorage.setItem(WALLPAPER_STORAGE_KEY, "nebula");
    expect(loadWallpaper()).toBe("rects");
  });
});

describe("WallpaperPicker", () => {
  it("offers every choice and reports the pick", async () => {
    const onChange = vi.fn();
    const { getByRole, findByRole } = render(
      <WallpaperPicker value="rects" onChange={onChange} />,
    );
    // Radix opens the dropdown on pointerdown, not click.
    fireEvent.pointerDown(getByRole("button", { name: "Wallpaper" }), {
      button: 0,
      ctrlKey: false,
    });
    for (const label of ["Plain", "Rounded rectangles", "Dots", "Rings"]) {
      expect(await findByRole("menuitem", { name: label })).toBeDefined();
    }
    fireEvent.click(await findByRole("menuitem", { name: "Dots" }));
    expect(onChange).toHaveBeenCalledWith("dots");
  });
});
