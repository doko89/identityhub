import { expect, test } from "@playwright/test";

// Login→dashboard flow (TECH_SPEC §9): a plain local user without MFA
// signs in and lands on the dashboard. Skips without seeded credentials
// (CI seeds TEST_E2E_USER via the admin API before running this spec).
const username = process.env.TEST_E2E_USER;
const password = process.env.TEST_E2E_PASSWORD;

test("login lands on the dashboard", async ({ page }) => {
  test.skip(username === undefined || password === undefined, "TEST_E2E_USER/PASSWORD not set");
  await page.goto("/login");
  await page.locator('input[name="username"]').fill(username as string);
  await page.locator('input[name="password"]').fill(password as string);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText(/Signed in as/)).toBeVisible({ timeout: 10_000 });
  expect(page.url()).not.toContain("/login");
});

test("wrong password stays on login with a notice", async ({ page }) => {
  await page.goto("/login");
  await page.locator('input[name="username"]').fill("no-such-user-e2e");
  await page.locator('input[name="password"]').fill("wrong-password-000");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toBeVisible({ timeout: 10_000 });
  expect(page.url()).toContain("/login");
});
