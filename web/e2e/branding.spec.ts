import { expect, test } from "@playwright/test";

// Public brand contract: the login page renders the org name from
// GET /api/branding and the endpoint keeps its key shape.
test("login page shows the brand", async ({ page }) => {
  const brandRes = await page.request.get("/api/branding");
  expect(brandRes.ok()).toBe(true);
  const body = (await brandRes.json()) as { branding: Record<string, unknown> };
  for (const key of [
    "org_name",
    "logo_url",
    "favicon_url",
    "primary_color",
    "theme",
    "login_background_url",
    "custom_css",
  ]) {
    expect(body.branding, `missing key ${key}`).toHaveProperty(key);
  }

  await page.goto("/login");
  await expect(page.getByRole("heading", { name: String(body.branding.org_name) })).toBeVisible();
  await expect(page.locator('input[name="username"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
});
