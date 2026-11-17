import { expect, test } from "@playwright/test";

// Password recovery pages render without authentication: the forgot form
// posts and shows the generic message, and reset without a token explains
// the dead link instead of calling the API.
test("forgot-password sends and shows the generic message", async ({ page }) => {
  await page.goto("/forgot-password");
  await expect(page.getByRole("heading", { name: /.+/ })).toBeVisible();
  await page.locator('input[name="login"]').fill("nobody@example.com");
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByText(/a reset link is on its way/)).toBeVisible({ timeout: 10_000 });
});

test("reset-password without a token asks for a new link", async ({ page }) => {
  await page.goto("/reset-password");
  await expect(page.getByText(/missing token/)).toBeVisible();
});

test("login links to forgot-password", async ({ page }) => {
  await page.goto("/login");
  await page.getByRole("link", { name: "Forgot password?" }).click();
  expect(page.url()).toContain("/forgot-password");
});
