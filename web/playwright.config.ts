import { defineConfig } from "@playwright/test";

// Login→dashboard e2e (TECH_SPEC §9) runs against a live `identityhub
// serve` (default http://localhost:8080). Brand/shape specs run
// unconditionally; the login spec needs TEST_E2E_USER/TEST_E2E_PASSWORD
// pointing at a plain local user without MFA, and skips without them.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:8080",
  },
});
