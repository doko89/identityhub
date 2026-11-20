import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Wallpaper } from "./Wallpaper";

afterEach(() => {
  cleanup();
});

describe("Wallpaper", () => {
  it("renders the brand pattern by default", () => {
    const { container } = render(<Wallpaper />);
    expect(container.querySelector("svg")).not.toBeNull();
  });

  it("renders nothing for a plain background", () => {
    const { container } = render(<Wallpaper background="plain" />);
    expect(container.innerHTML).toBe("");
  });

  it("renders the photo with a scrim, falling back without a URL", () => {
    const photo = render(<Wallpaper background="photo" photoUrl="/uploads/bg.webp" />);
    const img = photo.container.querySelector("img");
    expect(img?.getAttribute("src")).toBe("/uploads/bg.webp");
    expect(photo.container.querySelector(".bg-background\\/60")).not.toBeNull();
    photo.unmount();
    const fallback = render(<Wallpaper background="photo" />);
    expect(fallback.container.querySelector("svg")).not.toBeNull();
  });
});
