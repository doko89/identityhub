import { describe, expect, it } from "vitest";
import {
  gridClassFor,
  iconShapeClassFor,
  normalizeBackground,
  normalizeColumns,
  normalizeDensity,
  normalizeIconShape,
  resolveDashboardView,
} from "./theme";

describe("dashboard theme", () => {
  it("normalizes brand values with safe defaults", () => {
    expect(normalizeColumns(4)).toBe(4);
    expect(normalizeColumns("2")).toBe(2);
    expect(normalizeColumns(0)).toBe(3);
    expect(normalizeColumns(7)).toBe(3);
    expect(normalizeColumns(undefined)).toBe(3);
    expect(normalizeIconShape("circle")).toBe("circle");
    expect(normalizeIconShape("oval")).toBe("rounded");
    expect(normalizeDensity("compact")).toBe("compact");
    expect(normalizeDensity("airy")).toBe("comfortable");
    expect(normalizeBackground("photo")).toBe("photo");
    expect(normalizeBackground("video")).toBe("pattern");
  });

  it("resolves user overrides over brand defaults", () => {
    const brand = { dashboard_columns: 4, dashboard_density: "comfortable" };
    expect(resolveDashboardView(brand, { columns: null, density: null })).toEqual({
      columns: 4,
      density: "comfortable",
    });
    expect(resolveDashboardView(brand, { columns: 2, density: "compact" })).toEqual({
      columns: 2,
      density: "compact",
    });
    expect(resolveDashboardView(null, { columns: null, density: null })).toEqual({
      columns: 3,
      density: "comfortable",
    });
  });

  it("maps columns and shapes onto explicit classes", () => {
    expect(gridClassFor(2)).toBe("grid grid-cols-1 gap-3 sm:grid-cols-2");
    expect(gridClassFor(3)).toContain("lg:grid-cols-3");
    expect(gridClassFor(4)).toContain("lg:grid-cols-4");
    expect(iconShapeClassFor("rounded")).toBe("rounded-md");
    expect(iconShapeClassFor("circle")).toBe("rounded-full");
    expect(iconShapeClassFor("square")).toBe("rounded-none");
  });
});
