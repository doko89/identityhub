import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { PasswordChecklist, passwordRules } from "./PasswordChecklist";

afterEach(() => {
  cleanup();
});

describe("passwordRules", () => {
  it("accepts compliant passwords", () => {
    for (const pw of ["Abcdef1!", "P@ssw0rd", "Orang-tua-1!"]) {
      expect(passwordRules(pw).every((r) => r.met)).toBe(true);
    }
  });

  it("flags each missing piece", () => {
    const met = (pw: string): boolean[] => passwordRules(pw).map((r) => r.met);
    expect(met("Ab1!")).toEqual([false, true, true]);
    expect(met("abcdef1!")).toEqual([true, false, true]);
    expect(met("Abcdef12")).toEqual([true, true, false]);
    expect(met("")).toEqual([false, false, false]);
  });
});

describe("PasswordChecklist", () => {
  it("marks satisfied rules", () => {
    const { container } = render(<PasswordChecklist value="Abcdef1!" />);
    const rows = [...container.querySelectorAll("li")];
    expect(rows).toHaveLength(3);
    expect(rows.every((li) => li.getAttribute("data-met") === "true")).toBe(true);
    expect(rows[0]?.textContent).toContain("8 characters");
  });

  it("leaves unsatisfied rows muted", () => {
    const { container } = render(<PasswordChecklist value="abc" />);
    const rows = [...container.querySelectorAll("li")];
    expect(rows.every((li) => li.getAttribute("data-met") === "false")).toBe(true);
    expect(rows[0]?.className).toContain("text-muted-foreground");
  });
});
