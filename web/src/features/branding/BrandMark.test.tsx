import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { BrandMark } from "./BrandMark";

afterEach(() => {
  cleanup();
});

describe("BrandMark", () => {
  it("renders the labeled doorway mark", () => {
    const { getByRole } = render(<BrandMark className="size-8" />);
    const mark = getByRole("img", { name: "IdentityHub logo" });
    expect(mark.tagName).toBe("svg");
    expect(mark.getAttribute("class")).toContain("size-8");
  });
});
