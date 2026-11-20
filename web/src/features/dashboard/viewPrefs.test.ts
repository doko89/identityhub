import { afterEach, describe, expect, it } from "vitest";
import {
  getStoredColumns,
  getStoredDensity,
  setStoredColumns,
  setStoredDensity,
  VIEW_COLUMNS_KEY,
  VIEW_DENSITY_KEY,
} from "./viewPrefs";

afterEach(() => {
  localStorage.clear();
});

describe("viewPrefs", () => {
  it("returns null when nothing is stored", () => {
    expect(getStoredColumns()).toBeNull();
    expect(getStoredDensity()).toBeNull();
  });

  it("round-trips explicit choices", () => {
    setStoredColumns(4);
    setStoredDensity("compact");
    expect(localStorage.getItem(VIEW_COLUMNS_KEY)).toBe("4");
    expect(localStorage.getItem(VIEW_DENSITY_KEY)).toBe("compact");
    expect(getStoredColumns()).toBe(4);
    expect(getStoredDensity()).toBe("compact");
  });

  it("clears back to brand default with null", () => {
    setStoredColumns(2);
    setStoredDensity("compact");
    setStoredColumns(null);
    setStoredDensity(null);
    expect(localStorage.getItem(VIEW_COLUMNS_KEY)).toBeNull();
    expect(localStorage.getItem(VIEW_DENSITY_KEY)).toBeNull();
    expect(getStoredColumns()).toBeNull();
    expect(getStoredDensity()).toBeNull();
  });

  it("ignores unknown stored values so the brand default wins", () => {
    localStorage.setItem(VIEW_COLUMNS_KEY, "9");
    localStorage.setItem(VIEW_DENSITY_KEY, "airy");
    expect(getStoredColumns()).toBeNull();
    expect(getStoredDensity()).toBeNull();
  });
});
