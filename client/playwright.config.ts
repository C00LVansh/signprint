import { defineConfig, devices } from "@playwright/test";

const port = 4173;

export default defineConfig({
  testDir: "test-browser",
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: `http://127.0.0.1:${port}` },
  webServer: {
    command: "npm run build && node test-browser/serve.mjs",
    url: `http://127.0.0.1:${port}/blank.html`,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    {
      // private browsing is where IndexedDB + CryptoKey has historically broken
      name: "firefox-private",
      use: {
        ...devices["Desktop Firefox"],
        launchOptions: { firefoxUserPrefs: { "browser.privatebrowsing.autostart": true } },
      },
    },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
