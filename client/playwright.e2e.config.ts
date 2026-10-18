// Config for the full-stack test in crates/signprint-proxy/tests/e2e/browser.sh.
// That script starts the proxy and upstream; this just points browsers at it.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "https://localhost:18443",
    // the e2e stack uses a throwaway self-signed certificate
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
