import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const webRequire = createRequire(
  new URL("../apps/web/package.json", import.meta.url),
);
const { chromium, expect: browserExpect } = webRequire("@playwright/test");
const working = mkdtempSync(join(tmpdir(), "veriq-auth-"));
const port = process.env.VERIQ_AUTH_E2E_PORT ?? "18459";
const origin = `https://127.0.0.1:${port}`;
const project = "veriq-auth-security-e2e";
const env = {
  ...process.env,
  COMPOSE_PROJECT_NAME: project,
  VERIQ_TEST_LOGIN_PORT: port,
  VERIQ_TEST_AUTH_PORT: port,
  VERIQ_TEST_TLS_CERT: join(working, "cert.pem"),
  VERIQ_TEST_TLS_KEY: join(working, "key.pem"),
  VERIQ_TEST_MFA_KEYRING: join(working, "keyring.json"),
  VERIQ_TEST_PASSWORD_BLOCKLIST: join(working, "blocklist.sha256"),
  VERIQ_TEST_MAIL_KEY: randomBytes(32).toString("base64url") + "=",
};
const hex = () => randomBytes(32).toString("hex");
for (const key of [
  "VERIQ_DB_PASSWORD",
  "VERIQ_API_DB_PASSWORD",
  "VERIQ_WORKER_DB_PASSWORD",
  "VERIQ_TEST_LOGIN_VERIFIER_PASSWORD",
  "VERIQ_TEST_LOGIN_ISSUER_PASSWORD",
  "VERIQ_TEST_MFA_DB_PASSWORD",
  "VERIQ_TEST_AUTH_HMAC_KEY",
  "VERIQ_TEST_CSRF_KEY",
])
  env[key] = hex();

const overlays = [
  "compose.yaml",
  "compose.registration-test.yaml",
  "compose.login-test.yaml",
  "compose.mfa-test.yaml",
  "compose.password-recovery-test.yaml",
  "compose.mfa-recovery-test.yaml",
  "compose.organization-joining-test.yaml",
  "compose.bulk-import-test.yaml",
  "compose.academic-catalog-test.yaml",
  join(working, "scratch.yaml"),
].flatMap((file) => ["-f", file]);

let phase = "prepare isolated environment";
function check(condition, message) {
  if (!condition) throw new Error(message);
}

function command(binary, args, input) {
  const result = spawnSync(binary, args, {
    cwd: root,
    env,
    input,
    encoding: "utf8",
    timeout: 240_000,
  });
  check(
    result.status === 0,
    `${phase}: command failed (${binary}, exit ${result.status})`,
  );
  return result.stdout.trim();
}

const compose = (...args) =>
  command("docker", ["compose", ...overlays, ...args]);
const sql = (statement) =>
  command(
    "docker",
    [
      "compose",
      ...overlays,
      "exec",
      "-T",
      "postgres",
      "psql",
      "-U",
      "veriq_dev",
      "-d",
      "veriq",
      "-At",
      "-v",
      "ON_ERROR_STOP=1",
    ],
    statement,
  );

async function browserClient(browser) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto(origin + "/api/v1/health/live");
  return { context, page };
}

async function call(client, path, data, options = {}) {
  return client.page.evaluate(
    async ({ path, data, options }) => {
      const headers = { ...options.headers };
      if (data !== undefined && options.csrf !== false) {
        const reply = await fetch("/api/v1/auth/csrf", {
          headers: { "X-Veriq-CSRF-Bootstrap": "1" },
        });
        if (!reply.ok) return { status: reply.status };
        headers["X-CSRF-Token"] = (await reply.json()).csrf_token;
      }
      const start = performance.now();
      let response;
      try {
        response = await fetch("/api/v1" + path, {
          method: data === undefined ? "GET" : "POST",
          headers:
            data === undefined
              ? headers
              : {
                  "Content-Type": options.type ?? "application/json",
                  ...headers,
                },
          body:
            data === undefined
              ? undefined
              : options.binary
                ? new Uint8Array(data)
                : options.type
                  ? data
                  : JSON.stringify(data),
        });
      } catch {
        return { status: 0 };
      }
      const raw = await response.text();
      let body;
      try {
        body = JSON.parse(raw);
      } catch {
        body = undefined;
      }
      return {
        status: response.status,
        body,
        ms: performance.now() - start,
        empty: raw === "",
      };
    },
    { path, data, options },
  );
}

async function expect(client, path, body, status, options) {
  const actual = await call(client, path, body, options);
  check(
    actual.status === status,
    `${phase}: ${path} expected ${status}, got ${actual.status}`,
  );
  return actual.body;
}

async function mail(email, kind) {
  const script = `import json, pathlib, sys
for file in pathlib.Path('/run/veriq/mailbox').glob('*.json'):
    item = json.loads(file.read_text())
    if item.get('recipient') == sys.argv[1] and sys.argv[2] in item.get('path', ''):
        print(item['path'])
        break
`;
  for (let attempt = 0; attempt < 18; attempt++) {
    const link = compose(
      "exec",
      "-T",
      "worker",
      "python",
      "-c",
      script,
      email,
      kind,
    );
    if (link) return link;
    await delay(500);
  }
  throw new Error(`${phase}: local mailbox did not deliver proof`);
}

async function register(client, credentials) {
  await expect(client, "/auth/register", credentials, 202, { csrf: false });
  await expect(client, "/auth/login", credentials, 401);
  const link = await mail(credentials.email, "/verify-email#");
  const [path, proof] = link.split("#");
  const response = await client.context.request.get(origin + path);
  check(response.status() === 200, "verification page unavailable");
  await expect(client, "/auth/login", credentials, 401);
  await expect(client, "/auth/verify-email", { ...credentials, proof }, 204, {
    csrf: false,
  });
  await expect(client, "/auth/verify-email", { ...credentials, proof }, 400, {
    csrf: false,
  });
}

function totp(seed, offset = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0,
    bits = 0;
  const bytes = [];
  for (const symbol of seed.replace(/=+$/, "")) {
    buffer = (buffer << 5) | alphabet.indexOf(symbol);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 255);
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offset));
  const mac = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String(
    (mac.readUInt32BE(mac[19] & 15) & 0x7fffffff) % 1_000_000,
  ).padStart(6, "0");
}

function describe(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const round = (value) => Math.round(value * 10) / 10;
  return {
    n: sorted.length,
    median: round(
      (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2,
    ),
    min: round(sorted[0]),
    max: round(sorted.at(-1)),
  };
}

async function timing(client, existing, password) {
  const categories = [
    ["login", "/auth/login", 401, (email) => ({ email, password })],
    ["registration", "/auth/register", 202, (email) => ({ email, password })],
    [
      "password_reset",
      "/auth/password-reset/request",
      202,
      (email) => ({ email }),
    ],
  ];
  for (const [label, path, status, body] of categories) {
    const samples = [[], []];
    for (let i = 0; i < 8; i++) {
      const side = i % 2;
      const email = side ? `${randomUUID()}@example.invalid` : existing;
      const result = await call(client, path, body(email), {
        csrf: label !== "registration",
      });
      check(
        result.status === status &&
          result.empty === (status === 202) &&
          (status !== 401 ||
            result.body?.error?.code === "INVALID_CREDENTIALS"),
        `timing ${label}: unexpected response class ${result.status}`,
      );
      samples[side].push(result.ms);
    }
    console.log(
      JSON.stringify({
        timing: label,
        unit: "ms",
        known: describe(samples[0]),
        unknown: describe(samples[1]),
      }),
    );
  }
}

async function importTiming(operator, route, existing) {
  const samples = [[], []];
  for (let index = 0; index < 8; index++) {
    const side = index % 2;
    const email = side ? `${randomUUID()}@example.invalid` : existing;
    const result = await call(
      operator,
      route + "/preview",
      `email,marker\n${email},${index}\n`,
      { type: "text/csv" },
    );
    check(
      result.status === 200 &&
        result.body.counts.pending_onboarding === 1 &&
        result.body.rows[0].request_id === null,
      "bulk timing probe disclosed account state",
    );
    samples[side].push(result.ms);
  }
  console.log(
    JSON.stringify({
      timing: "bulk_preview",
      unit: "ms",
      known: describe(samples[0]),
      unknown: describe(samples[1]),
    }),
  );
}
function workbook(email) {
  const script = `import base64, io, sys, zipfile
ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
rel='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
output=io.BytesIO()
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('xl/workbook.xml',f'<workbook xmlns="{ns}" xmlns:r="{rel}"><sheets><sheet r:id="rId1"/></sheets></workbook>')
    z.writestr('xl/_rels/workbook.xml.rels',f'<Relationships><Relationship Id="rId1" Type="{rel}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
    z.writestr('xl/worksheets/sheet1.xml',f'<worksheet xmlns="{ns}"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Email</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>{sys.argv[1]}</t></is></c></row></sheetData></worksheet>')
print(base64.b64encode(output.getvalue()).decode())
`;
  return Array.from(
    Buffer.from(
      compose("exec", "-T", "worker", "python", "-c", script, email),
      "base64",
    ),
  );
}

function runtimePrivileges() {
  sql(`
    BEGIN;
    SET LOCAL ROLE veriq_api;
    DO $$ BEGIN
      IF has_function_privilege(current_user,'public.veriq_auth_issue(uuid,bytea,uuid,bytea,interval[],uuid,uuid,uuid)','EXECUTE')
      THEN RAISE EXCEPTION 'runtime can issue credentials'; END IF;
      BEGIN
        PERFORM public.veriq_auth_issue(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
        RAISE EXCEPTION 'issuer execution was allowed';
      EXCEPTION WHEN insufficient_privilege THEN NULL;
      END;
      IF public.veriq_user_import(NULL,NULL,NULL,NULL,'result',NULL,NULL,NULL) IS NOT NULL
      THEN RAISE EXCEPTION 'import accepted missing identity'; END IF;
    END $$;
    ROLLBACK;
    BEGIN;
    SET LOCAL ROLE veriq_worker;
    DO $$ BEGIN
      BEGIN
        PERFORM public.veriq_user_import(NULL,NULL,NULL,NULL,'result',NULL,NULL,NULL);
        RAISE EXCEPTION 'worker execution was allowed';
      EXCEPTION WHEN insufficient_privilege THEN NULL;
      END;
    END $$;
    ROLLBACK;
  `);
}
async function catalogJourney(operator, org, other) {
  const base = `/organizations/${org}/academic/courses`;
  const denied = await operator.context.request.post(
    origin + "/api/v1" + base,
    {
      headers: { Origin: origin, "Idempotency-Key": randomUUID() },
      data: { title: "No CSRF" },
    },
  );
  check(denied.status() === 403, "catalog accepted mutation without CSRF");

  const bootstrap = await operator.context.request.get(
    origin + "/api/v1/auth/csrf",
    {
      headers: { "X-Veriq-CSRF-Bootstrap": "1" },
    },
  );
  check(bootstrap.ok(), "catalog CSRF bootstrap failed");
  const foreign = await operator.context.request.post(
    origin + "/api/v1" + base,
    {
      headers: {
        Origin: "https://example.invalid",
        "Idempotency-Key": randomUUID(),
        "X-CSRF-Token": (await bootstrap.json()).csrf_token,
      },
      data: { title: "Wrong origin" },
    },
  );
  check(foreign.status() === 403, "catalog accepted a foreign Origin");
  const page = await operator.context.newPage();
  const dist = join(root, "apps/web/dist");
  await page.route(origin + "/academic/**", (route) =>
    route.fulfill({
      path: join(dist, "index.html"),
      contentType: "text/html",
    }),
  );
  await page.route(origin + "/assets/**", (route) => {
    const asset = new URL(route.request().url()).pathname.split("/").at(-1);
    check(
      asset && /^[a-zA-Z0-9._-]+$/.test(asset),
      "invalid fixture asset path",
    );
    return route.fulfill({ path: join(dist, "assets", asset) });
  });
  phase = "Academic catalog Vue assets and initial render";
  await page.goto(origin + "/academic/" + org);
  await browserExpect(
    page.getByRole("heading", { name: "Учебная структура" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Создать" }).click();
  await page.getByRole("textbox", { name: "Название" }).fill("Каталог fixture");
  await page.getByRole("textbox", { name: "Описание" }).fill("Описание курса");
  await page.getByRole("button", { name: "Сохранить" }).click();
  phase = "Academic catalog Vue create, edit and archive";
  const row = page.getByRole("row", { name: /Каталог fixture/ });
  await browserExpect(row).toBeVisible();
  await row.getByRole("button", { name: "Редактировать" }).click();
  await page
    .getByRole("textbox", { name: "Название" })
    .fill("Архивируемый курс");
  await page.getByRole("button", { name: "Сохранить" }).click();
  const revised = page.getByRole("row", { name: /Архивируемый курс/ });
  await revised.getByRole("button", { name: "Архивировать" }).click();
  await page
    .getByRole("group", { name: "Архивировать" })
    .getByRole("button", { name: "Архивировать" })
    .click();
  await browserExpect(revised).toHaveCount(0);
  await page
    .getByRole("combobox", { name: "Архив", exact: true })
    .selectOption({ label: "Архив" });
  await browserExpect(revised).toBeVisible();
  await page
    .getByRole("textbox", { name: "Поиск по названию" })
    .fill("нет совпадения");
  await browserExpect(page.getByText("Записей нет")).toBeVisible();
  await page.getByRole("textbox", { name: "Поиск по названию" }).fill("");
  await browserExpect(revised).toBeVisible();

  phase = "Academic catalog Vue group creation and tenant switch";
  const catalogSelect = page.getByRole("combobox", {
    name: "Учебная структура",
  });
  await catalogSelect.selectOption("study_groups");
  await page
    .getByRole("combobox", { name: "Архив", exact: true })
    .selectOption({ label: "Активные" });
  await page.getByRole("button", { name: "Создать" }).click();
  await page.getByRole("textbox", { name: "Название" }).fill("Группа fixture");
  await page.getByRole("button", { name: "Сохранить" }).click();
  const group = page.getByRole("row", { name: /Группа fixture/ });
  await browserExpect(group).toBeVisible();
  await expect(
    operator,
    "/auth/sessions/rotate",
    { organization_id: other },
    204,
  );
  await page.evaluate((tenant) => {
    history.pushState({}, "", "/academic/" + tenant);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, other);
  await browserExpect(page.getByRole("alert")).toContainText(
    "Недостаточно прав",
  );
  await browserExpect(group).toHaveCount(0);
  await page.getByRole("combobox", { name: "Язык" }).selectOption("en");
  await browserExpect(
    page.getByRole("heading", { name: "Academic catalog" }),
  ).toBeVisible();
  await page.close();
  await expect(
    operator,
    "/auth/sessions/rotate",
    { organization_id: org },
    204,
  );
}
async function run(browser) {
  const client = await browserClient(browser);
  const password = randomBytes(24).toString("hex");
  const changed = randomBytes(24).toString("hex");
  const credentials = { email: "student@example.invalid", password };
  const staff = { email: "staff@example.invalid", password };
  const org = randomUUID(),
    other = randomUUID();
  const sessionName = "__Host-veriq-session";

  phase = "registration and session lifecycle";
  await register(client, credentials);
  await expect(
    client,
    "/auth/login",
    { ...credentials, password: changed },
    401,
  );
  await expect(client, "/auth/login", credentials, 403, { csrf: false });
  const fixed = await browserClient(browser);
  await fixed.context.addCookies([
    {
      name: sessionName,
      value: `${randomBytes(16).toString("hex")}.${randomBytes(32).toString("base64url")}`,
      url: origin,
      secure: true,
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
  await expect(fixed, "/auth/login", credentials, 409);
  await expect(fixed, "/me", undefined, 401);
  await fixed.context.close();
  await expect(client, "/auth/login", credentials, 204);
  const original = (await client.context.cookies()).find(
    (cookie) => cookie.name === sessionName,
  );
  check(
    original?.secure && original.httpOnly && original.sameSite === "Lax",
    "cookie attributes",
  );
  check(
    !(await client.page.evaluate(() => document.cookie)).includes(sessionName),
    "script-visible session",
  );
  const csrfReply = await client.context.request.get(
    origin + "/api/v1/auth/csrf",
    {
      headers: { "X-Veriq-CSRF-Bootstrap": "1" },
    },
  );
  check(csrfReply.ok(), "CSRF bootstrap unavailable");
  const originProbe = (await csrfReply.json()).csrf_token;
  const originDenial = await client.context.request.post(
    origin + "/api/v1/auth/logout",
    {
      headers: {
        Origin: "https://example.invalid",
        "X-CSRF-Token": originProbe,
      },
      data: {},
    },
  );
  check(originDenial.status() === 403, "cross-origin request accepted");
  await expect(client, "/auth/sessions/rotate", { organization_id: org }, 401);
  await expect(client, "/auth/sessions/rotate", { organization_id: null }, 204);
  const rotated = (await client.context.cookies()).find(
    (cookie) => cookie.name === sessionName,
  );
  check(
    rotated && rotated.value !== original.value,
    "rotation did not replace token",
  );
  const replay = await browserClient(browser);
  await replay.context.addCookies([original]);
  await expect(replay, "/me", undefined, 401);
  await replay.context.close();
  const otherSession = await browserClient(browser);
  await expect(otherSession, "/auth/login", credentials, 204);
  await expect(
    client,
    "/auth/password/change",
    { current_password: password, new_password: changed },
    204,
  );
  await expect(otherSession, "/me", undefined, 401);
  await expect(
    client,
    "/auth/login",
    { ...credentials, password: changed },
    204,
  );
  await otherSession.context.clearCookies();
  await expect(
    otherSession,
    "/auth/login",
    { ...credentials, password: changed },
    204,
  );
  await expect(client, "/auth/sessions/revoke", {}, 204);
  await expect(otherSession, "/me", undefined, 401);
  await expect(
    client,
    "/auth/login",
    { ...credentials, password: changed },
    204,
  );

  phase = "MFA enrollment, recovery codes, step-up and tenant isolation";
  const operator = await browserClient(browser);
  await register(operator, staff);
  const staffId = sql(
    "SELECT id FROM users WHERE email_normalized='staff@example.invalid';",
  );
  check(/^[a-f0-9-]{36}$/.test(staffId), "invalid fixture id");
  sql(`
    INSERT INTO organizations(id,slug,display_name,timezone,status) VALUES
      ('${org}','org-one','One','UTC','active'),('${other}','org-two','Two','UTC','active');
    INSERT INTO organization_memberships(id,organization_id,user_id,status) VALUES
      ('${staffId}','${org}','${staffId}','active'),
      (gen_random_uuid(),'${other}','${staffId}','active');
    INSERT INTO organization_roles VALUES ('${org}','${staffId}','org_admin');
    INSERT INTO organization_role_permissions (organization_id,role_id,permission_code) VALUES
      ('${org}','${staffId}','organization.join.manage'),
      ('${org}','${staffId}','organization.import.manage'),
      ('${org}','${staffId}','academic.catalog.read'),
      ('${org}','${staffId}','academic.catalog.archive'),
      ('${org}','${staffId}','academic.catalog.manage');
    INSERT INTO membership_roles (organization_id,membership_id,role_id) VALUES ('${org}','${staffId}','${staffId}');
    INSERT INTO mfa_recovery_sources(user_id,organization_id,source_id) VALUES ('${staffId}','${org}',gen_random_uuid());
  `);
  await expect(
    operator,
    "/auth/login",
    { ...staff, organization_id: other },
    204,
  );
  await expect(
    operator,
    "/auth/sessions/rotate",
    { organization_id: org },
    401,
  );
  await expect(operator, "/auth/logout", {}, 204);
  compose(
    "exec",
    "-T",
    "api",
    "python",
    "-c",
    "from pathlib import Path; Path('/tmp/veriq-e2e-mfa').mkdir(mode=0o700)",
  );
  const seedPath = "/tmp/veriq-e2e-mfa/seed";
  compose(
    "exec",
    "-T",
    "api",
    "python",
    "-m",
    "veriq.mfa_admin",
    "--user",
    staffId,
    "--output",
    seedPath,
  );
  const seed = compose("exec", "-T", "api", "cat", seedPath);
  compose("exec", "-T", "api", "rm", seedPath);
  await expect(
    operator,
    "/auth/login",
    { ...staff, organization_id: org },
    202,
  );
  await expect(operator, "/me", undefined, 401);
  const enrollmentCode = totp(seed, -1);
  const enrollment = await expect(
    operator,
    "/auth/mfa/challenge",
    { code: enrollmentCode },
    200,
  );
  check(enrollment.recovery_codes.length === 10, "recovery codes not returned");
  await expect(operator, "/auth/logout", {}, 204);
  await expect(
    operator,
    "/auth/login",
    { ...staff, organization_id: org },
    202,
  );
  await expect(operator, "/auth/mfa/challenge", { code: enrollmentCode }, 401);
  await expect(
    operator,
    "/auth/mfa/challenge",
    { code: enrollment.recovery_codes[0], recovery: true },
    204,
  );
  const another = await browserClient(browser);
  await expect(another, "/auth/login", { ...staff, organization_id: org }, 202);
  await expect(
    another,
    "/auth/mfa/challenge",
    { code: enrollment.recovery_codes[0], recovery: true },
    401,
  );
  const joining = `/organizations/${org}/joining`;
  await expect(operator, joining, { action: "set_intake", enabled: true }, 404);
  await expect(operator, "/auth/mfa/step-up", { purpose: "sensitive" }, 202);
  await expect(operator, "/auth/mfa/challenge", { code: totp(seed) }, 429);
  // Reset only the dedicated ephemeral Redis test instance after asserting its budget.
  compose("exec", "-T", "redis", "redis-cli", "FLUSHDB");
  await expect(operator, "/auth/mfa/challenge", { code: totp(seed) }, 204);
  await expect(operator, joining, { action: "set_intake", enabled: true }, 200);
  await expect(
    operator,
    `/organizations/${other}/joining`,
    { action: "set_intake", enabled: true },
    404,
  );

  phase = "joining and bulk claim";
  const applicant = { email: "applicant@example.invalid", password };
  await register(another, applicant);
  await expect(another, "/auth/login", applicant, 204);
  const application = await expect(another, joining, { action: "apply" }, 200);
  check(
    application.status === "pending",
    "application did not create pending membership",
  );
  await expect(
    operator,
    joining,
    { action: "approve", object_id: application.request_id },
    200,
  );
  const studentId = sql(
    "SELECT id FROM users WHERE email_normalized='student@example.invalid';",
  );
  const invite = await expect(
    operator,
    joining,
    { action: "issue_invite", recipient_id: studentId, enabled: true },
    200,
  );
  await expect(
    client,
    `/organizations/${other}/joining`,
    {
      action: "redeem_invite",
      object_id: invite.object_id,
      secret: invite.secret,
    },
    404,
  );
  const redeemed = await expect(
    client,
    joining,
    {
      action: "redeem_invite",
      object_id: invite.object_id,
      secret: invite.secret,
    },
    200,
  );
  check(
    redeemed.status === "active",
    "personal invitation did not activate membership",
  );
  const imports = `/organizations/${other}/imports`;
  await expect(
    operator,
    imports + "/preview",
    "email\na@example.invalid\n",
    404,
    { type: "text/csv" },
  );
  const claimant = { email: "claimant@example.invalid", password };
  const claimClient = await browserClient(browser);
  await register(claimClient, claimant);
  await expect(claimClient, "/auth/login", claimant, 204);
  const importRoute = `/organizations/${org}/imports`;
  const preview = await expect(
    operator,
    importRoute + "/preview",
    `email\n${claimant.email}\nmissing@example.invalid\n`,
    200,
    { type: "text/csv" },
  );
  check(
    preview.counts.pending_onboarding === 2,
    "import disclosed global account state",
  );
  const confirmed = await expect(
    operator,
    importRoute + "/confirm",
    { batch_id: preview.batch_id, version: preview.version },
    200,
  );
  check(
    confirmed.rows.every((row) => row.request_id === null),
    "unclaimed import has request ID",
  );
  const claim = await expect(
    claimClient,
    importRoute + "/claim",
    { batch_id: preview.batch_id },
    200,
  );
  check(
    claim.status === "pending",
    "import claim did not create pending membership",
  );
  const spreadsheetUser = { email: "spreadsheet@example.invalid", password };
  const spreadsheet = await browserClient(browser);
  const xlsx = await expect(
    operator,
    importRoute + "/preview",
    workbook(spreadsheetUser.email),
    200,
    {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      binary: true,
    },
  );
  await expect(
    operator,
    importRoute + "/confirm",
    { batch_id: xlsx.batch_id, version: xlsx.version },
    200,
  );
  await register(spreadsheet, spreadsheetUser);
  await expect(spreadsheet, "/auth/login", spreadsheetUser, 204);
  const sheetClaim = await expect(
    spreadsheet,
    importRoute + "/claim",
    { batch_id: xlsx.batch_id },
    200,
  );
  check(
    sheetClaim.status === "pending",
    "XLSX claim did not create pending membership",
  );
  const sampled = await browserClient(browser);
  const sampledAddress = { email: `${randomUUID()}@example.invalid`, password };
  await register(sampled, sampledAddress);
  // Start a fresh budget after completing the CSV/XLSX import workflows.
  compose("exec", "-T", "redis", "redis-cli", "FLUSHDB");
  await importTiming(operator, importRoute, sampledAddress.email);
  runtimePrivileges();

  phase = "Academic catalog Vue and HTTPS tenant switch";
  await catalogJourney(operator, org, other);
  phase = "independent recovery, reset and outage";
  await expect(operator, "/auth/mfa/recovery", staff, 202);
  const caseId = sql(
    `SELECT id FROM mfa_recovery_requests WHERE user_id='${staffId}';`,
  );
  check(/^[a-f0-9-]{36}$/.test(caseId), "recovery request not persisted");
  await expect(
    operator,
    `/auth/mfa/recovery/${caseId}/action`,
    { action: "approve", operation_id: randomUUID() },
    404,
  );
  const sampler = await browserClient(browser);
  await timing(sampler, claimant.email, changed);
  const csrf = await sampler.page.evaluate(
    async () =>
      (
        await (
          await fetch("/api/v1/auth/csrf", {
            headers: { "X-Veriq-CSRF-Bootstrap": "1" },
          })
        ).json()
      ).csrf_token,
  );
  const concurrent = await Promise.all(
    Array.from({ length: 8 }, () =>
      call(
        sampler,
        "/auth/login",
        {
          email: `${randomUUID()}@example.invalid`,
          password: changed,
        },
        {
          csrf: false,
          headers: { "X-CSRF-Token": csrf, "X-Forwarded-For": "203.0.113.4" },
        },
      ),
    ),
  );
  check(
    concurrent.some(({ status }) => status === 503) &&
      concurrent.every(({ status }) => status === 401 || status === 503),
    "concurrent Argon2 admission limit did not reject excess work",
  );
  await expect(
    sampler,
    "/auth/password-reset/request",
    { email: staff.email },
    202,
  );
  const resetLink = await mail(staff.email, "/password-reset/confirm#");
  const [resetPath, resetProof] = resetLink.split("#");
  const resetPage = await operator.context.request.get(origin + resetPath);
  check(resetPage.status() === 200, "reset page unavailable");
  await expect(
    operator,
    "/auth/password-reset/confirm",
    { email: staff.email, password: changed, proof: resetProof },
    204,
  );
  await expect(
    operator,
    "/auth/password-reset/confirm",
    { email: staff.email, password: changed, proof: resetProof },
    400,
  );
  await operator.context.clearCookies();
  await expect(
    operator,
    "/auth/login",
    { ...staff, password: changed, organization_id: org },
    202,
  );
  await expect(operator, "/me", undefined, 401);
  compose("stop", "redis");
  await expect(
    sampler,
    "/auth/login",
    { ...credentials, password: changed },
    503,
  );
  await expect(client, "/me", undefined, 200);
  compose("start", "redis");
  compose("up", "--wait", "--wait-timeout", "90");
  compose("stop", "api");
  check(
    (await call(client, "/me")).status === 0,
    "API stop did not reach browser",
  );
  compose("start", "api");
  compose("up", "--wait", "--wait-timeout", "90");
  await expect(client, "/me", undefined, 200);
  console.log("HTTPS browser journey passed");
}

let started = false;
let browser;
try {
  writeFileSync(
    join(working, "scratch.yaml"),
    "services:\n  postgres:\n    volumes: !override\n      - type: tmpfs\n        target: /var/lib/postgresql/data\n",
  );
  writeFileSync(
    env.VERIQ_TEST_MFA_KEYRING,
    JSON.stringify({ active: "fixture", keys: { fixture: hex() } }),
  );
  writeFileSync(
    env.VERIQ_TEST_PASSWORD_BLOCKLIST,
    createHash("sha256").update("fixture blocklist marker").digest("hex") +
      "\n",
  );
  command(process.env.VERIQ_E2E_OPENSSL ?? "openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
    "-keyout",
    env.VERIQ_TEST_TLS_KEY,
    "-out",
    env.VERIQ_TEST_TLS_CERT,
  ]);
  if (process.platform !== "win32")
    command("chmod", ["644", env.VERIQ_TEST_TLS_KEY]);
  check(!compose("ps", "-aq"), "dedicated test project is already active");
  env.VERIQ_DB_NAME = "veriq";
  started = true;
  compose("up", "--build", "--wait", "--wait-timeout", "120");
  browser = await chromium.launch();
  await run(browser);
} catch (error) {
  console.error(
    error instanceof Error && error.constructor === Error
      ? error.message
      : `${phase}: browser or setup failure`,
  );
  process.exitCode = 1;
} finally {
  try {
    await browser?.close();
    if (started) compose("down");
  } finally {
    for (const file of [
      env.VERIQ_TEST_TLS_CERT,
      env.VERIQ_TEST_TLS_KEY,
      env.VERIQ_TEST_MFA_KEYRING,
      env.VERIQ_TEST_PASSWORD_BLOCKLIST,
      join(working, "scratch.yaml"),
    ])
      rmSync(file, { force: true });
    rmdirSync(working);
  }
}
