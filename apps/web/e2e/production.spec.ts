import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const allowedProjects = new Set(["veriq-prod-ci", "veriq-prod-smoke"]);

function compose(command: "stop" | "start", service: "api" | "redis") {
  execFileSync(
    "docker",
    [
      "compose",
      "-f",
      "compose.yaml",
      "-f",
      "compose.prod.yaml",
      command,
      service,
    ],
    {
      cwd: repo,
      timeout: 45_000,
      stdio: "inherit",
    },
  );
}

function observeBrowser(page: Page, baseURL: string) {
  const errors: string[] = [];
  const foreignRequests: string[] = [];
  const origin = new URL(baseURL).origin;
  let expectedHttpFailure = false;
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    const healthUrl = message
      .location()
      .url.startsWith(`${origin}/api/v1/health/`);
    if (
      expectedHttpFailure &&
      healthUrl &&
      /^Failed to load resource:.*\b50[234]\b/.test(message.text())
    ) {
      return;
    }
    errors.push(message.text());
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.origin !== origin
    ) {
      foreignRequests.push(url.origin);
    }
  });
  return {
    expectHttpFailure: (value: boolean) => {
      expectedHttpFailure = value;
    },
    verify: () => {
      expect(errors).toEqual([]);
      expect(foreignRequests).toEqual([]);
    },
  };
}

async function apiStatus(request: APIRequestContext, probe: "live" | "ready") {
  return (
    await request.get(`/api/v1/health/${probe}`, { timeout: 5_000 })
  ).status();
}

async function expectHealthy(page: Page) {
  await expect(
    page.getByRole("status", { name: "Доступность API" }),
  ).toHaveText("API отвечает.");
  await expect(
    page.getByRole("status", { name: "Готовность системы" }),
  ).toHaveText("API, PostgreSQL и Redis доступны.");
}

test.beforeAll(() => {
  if (!allowedProjects.has(process.env.COMPOSE_PROJECT_NAME ?? "")) {
    throw new Error(
      "Run browser tests against the dedicated production smoke project",
    );
  }
});

test("serves built assets, routes and both languages from one origin", async ({
  page,
  request,
  baseURL,
}) => {
  const browser = observeBrowser(page, baseURL!);
  const scripts: string[] = [];
  const styles: string[] = [];
  page.on("response", (response) => {
    if (
      !new URL(response.url()).pathname.startsWith("/assets/") ||
      !response.ok()
    )
      return;
    const mime = response.headers()["content-type"] ?? "";
    if (mime.includes("javascript")) scripts.push(response.url());
    if (mime.includes("text/css")) styles.push(response.url());
  });
  const response = await page.goto("/status");
  expect(response?.status()).toBe(200);
  expect(response?.headers()["content-type"]).toContain("text/html");
  expect(response?.headers()["cache-control"]).toContain("no-cache");
  await expect(
    page.getByRole("heading", { name: "Состояние Veriq" }),
  ).toBeVisible();
  await expectHealthy(page);
  expect(scripts.length).toBeGreaterThan(0);
  expect(styles.length).toBeGreaterThan(0);
  expect((await request.get(scripts[0]!)).headers()["cache-control"]).toContain(
    "max-age=31536000",
  );
  expect((await request.get("/assets/missing.js")).status()).toBe(404);
  expect((await request.get("/api/v1/docs")).status()).toBe(404);

  await page.getByRole("combobox", { name: "Язык" }).selectOption("en");
  await expect(
    page.getByRole("heading", { name: "Veriq status" }),
  ).toBeVisible();
  await expect(page.getByRole("status", { name: "API liveness" })).toHaveText(
    "The API is responding.",
  );
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.getByRole("combobox", { name: "Language" }).selectOption("ru");
  await expect(page.locator("html")).toHaveAttribute("lang", "ru");
  await page.getByRole("link", { name: "Veriq · Состояние" }).click();
  await expect(page).toHaveURL(new URL("/", baseURL!).href);
  expect((await page.goto("/unknown/route"))?.status()).toBe(200);
  await expect(page).toHaveURL(new URL("/", baseURL!).href);
  await expectHealthy(page);
  browser.verify();
});

test("keeps liveness distinct from readiness during a Redis outage", async ({
  page,
  request,
  baseURL,
}) => {
  const browser = observeBrowser(page, baseURL!);
  await page.goto("/");
  await expectHealthy(page);
  browser.expectHttpFailure(true);
  compose("stop", "redis");
  try {
    await expect
      .poll(() => apiStatus(request, "ready"), { timeout: 15_000 })
      .toBe(503);
    expect(await apiStatus(request, "live")).toBe(200);
    await page.getByRole("button", { name: "Проверить снова" }).click();
    await expect(
      page.getByRole("status", { name: "Доступность API" }),
    ).toHaveText("API отвечает.");
    await expect(
      page.getByRole("status", { name: "Готовность системы" }),
    ).toHaveText("Проверка доступности не прошла.");
  } finally {
    compose("start", "redis");
  }
  await expect
    .poll(() => apiStatus(request, "ready"), { timeout: 30_000 })
    .toBe(200);
  browser.expectHttpFailure(false);
  await page.getByRole("button", { name: "Проверить снова" }).click();
  await expectHealthy(page);
  browser.verify();
});

test("serves the app while API is stopped and recovers on retry", async ({
  page,
  request,
  baseURL,
}) => {
  const browser = observeBrowser(page, baseURL!);
  await page.goto("/");
  await expectHealthy(page);
  browser.expectHttpFailure(true);
  compose("stop", "api");
  try {
    expect((await request.get("/_health/live")).status()).toBe(204);
    expect((await page.reload())?.status()).toBe(200);
    await expect(
      page.getByRole("heading", { name: "Состояние Veriq" }),
    ).toBeVisible();
    await expect(
      page.getByRole("status", { name: "Доступность API" }),
    ).toHaveText("API недоступен.");
    await expect(
      page.getByRole("status", { name: "Готовность системы" }),
    ).toHaveText("Проверка доступности не прошла.");
  } finally {
    compose("start", "api");
  }
  await expect
    .poll(() => apiStatus(request, "ready"), { timeout: 30_000 })
    .toBe(200);
  browser.expectHttpFailure(false);
  await page.getByRole("button", { name: "Проверить снова" }).click();
  await expectHealthy(page);
  browser.verify();
});

test("keeps test Auth endpoints disabled in production", async ({ page }) => {
  for (const route of [
    "/auth/csrf",
    "/me",
    "/auth/verify-email",
    "/organizations/00000000-0000-4000-8000-000000000001/academic/courses",
  ]) {
    expect((await page.request.get("/api/v1" + route)).status()).toBe(404);
  }
  for (const route of [
    "/auth/register",
    "/auth/login",
    "/auth/mfa/challenge",
    "/auth/password-reset/request",
    "/auth/mfa/recovery",
    "/organizations/00000000-0000-4000-8000-000000000001/joining",
    "/organizations/00000000-0000-4000-8000-000000000001/imports/preview",
  ]) {
    expect(
      (await page.request.post("/api/v1" + route, { data: {} })).status(),
    ).toBe(404);
  }
});
