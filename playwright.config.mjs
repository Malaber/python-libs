import { defineConfig } from "playwright/test";


export default defineConfig({
  testDir: "./tests-e2e",
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["line"], ["html", { outputFolder: "e2e-artifacts/report", open: "never" }]] : "line",
  use: {
    baseURL: "http://localhost:8765",
    browserName: "chromium",
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  outputDir: "e2e-artifacts/results",
});
