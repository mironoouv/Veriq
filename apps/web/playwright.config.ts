import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 90_000,
  reporter: "list",
  use: {
    baseURL: `http://127.0.0.1:${process.env.VERIQ_PROD_WEB_PORT ?? "8080"}`,
    browserName: "chromium",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
});
