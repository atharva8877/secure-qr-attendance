const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { after, before, test } = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const HMAC_SECRET = "integration-test-secret-with-at-least-32-bytes";
let serverProcess;
let vercelProcesses = [];
let baseUrl;
let vercelUrls = [];
let dataDirectory;

async function reservePort() {
  const listener = net.createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const { port } = listener.address();
  await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitUntilReady() {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (serverProcess.exitCode !== null) {
      throw new Error(`Test server exited with code ${serverProcess.exitCode}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/me`);
      if (response.ok) return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error("Test server did not become ready");
}

async function request(pathname, options = {}) {
  return fetch(`${baseUrl}${pathname}`, {
    ...options,
    headers: {
      ...(options.cookie ? { Cookie: options.cookie } : {}),
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
}

async function login(username, password) {
  const response = await request("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  const cookie = response.headers.get("set-cookie")?.split(";")[0];
  return { response, cookie };
}

function createToken(claims) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = crypto.createHmac("sha256", HMAC_SECRET).update(input).digest("base64url");
  return `${input}.${signature}`;
}

before(async () => {
  dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "secure-qr-attendance-"));
  const port = await reservePort();
  baseUrl = `http://127.0.0.1:${port}`;
  serverProcess = spawn(process.execPath, [path.join(ROOT, "src", "server.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDirectory,
      QR_HMAC_SECRET: HMAC_SECRET,
      ATTENDEE_PASSWORD: "test-attendee-password",
      SCANNER_PASSWORD: "test-scanner-password",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitUntilReady();

  for (let instance = 0; instance < 2; instance += 1) {
    const vercelPort = await reservePort();
    vercelUrls.push(`http://127.0.0.1:${vercelPort}`);
    vercelProcesses.push(
      spawn(process.execPath, [path.join(ROOT, "src", "server.js")], {
        cwd: ROOT,
        env: {
          ...process.env,
          PORT: String(vercelPort),
          DATA_DIR: dataDirectory,
          VERCEL: "1",
          QR_HMAC_SECRET: HMAC_SECRET,
          ATTENDEE_PASSWORD: "test-attendee-password",
          SCANNER_PASSWORD: "test-scanner-password",
        },
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
  }
  for (const vercelUrl of vercelUrls) {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`${vercelUrl}/api/me`);
        if (response.ok) break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
  }
});

after(async () => {
  for (const process of vercelProcesses) {
    if (process.exitCode === null) {
      process.kill();
      await once(process, "exit");
    }
  }
  if (serverProcess && serverProcess.exitCode === null) {
    serverProcess.kill();
    await once(serverProcess, "exit");
  }
  if (dataDirectory) await fs.rm(dataDirectory, { recursive: true, force: true });
});

test("signed QR tokens enforce roles, integrity, expiry, and one-time attendance", async () => {
  const unauthenticatedQr = await request("/api/qr");
  assert.equal(unauthenticatedQr.status, 401);

  const rejectedLogin = await login("student", "incorrect-password");
  assert.equal(rejectedLogin.response.status, 401);

  const attendeeLogin = await login("student", "test-attendee-password");
  assert.equal(attendeeLogin.response.status, 200);
  assert.match(attendeeLogin.response.headers.get("set-cookie"), /HttpOnly/);
  const attendeeCookie = attendeeLogin.cookie;
  assert.ok(attendeeCookie);

  const qrResponse = await request("/api/qr", { cookie: attendeeCookie });
  assert.equal(qrResponse.status, 200);
  const qr = await qrResponse.json();
  assert.match(qr.qrCode, /^data:image\/png;base64,/);
  const [, payloadPart] = qr.token.split(".");
  const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
  assert.equal(claims.sub, "attendee-001");
  assert.equal(claims.event, "event-2026-42");
  assert.equal(claims.exp - claims.iat, 60);

  const wrongRole = await request("/api/attendance", { cookie: attendeeCookie });
  assert.equal(wrongRole.status, 403);

  const scannerLogin = await login("staff", "test-scanner-password");
  assert.equal(scannerLogin.response.status, 200);
  const scannerCookie = scannerLogin.cookie;
  assert.ok(scannerCookie);

  const invalidOrigin = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    headers: { Origin: "https://attacker.example" },
    body: JSON.stringify({ token: qr.token }),
  });
  assert.equal(invalidOrigin.status, 403);

  const tamperedToken = `${qr.token.slice(0, qr.token.lastIndexOf(".") + 1)}${"A".repeat(43)}`;
  const tamperedScan = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    body: JSON.stringify({ token: tamperedToken }),
  });
  assert.equal(tamperedScan.status, 401);

  const successfulScan = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    body: JSON.stringify({ token: qr.token }),
  });
  assert.equal(successfulScan.status, 200);
  assert.equal((await successfulScan.json()).attendee, "Alex Morgan");

  const replay = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    body: JSON.stringify({ token: qr.token }),
  });
  assert.equal(replay.status, 409);

  const duplicateClaims = {
    ...claims,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60,
    jti: crypto.randomUUID(),
  };
  const duplicate = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    body: JSON.stringify({ token: createToken(duplicateClaims) }),
  });
  assert.equal(duplicate.status, 409);

  const expiredClaims = {
    ...duplicateClaims,
    iat: Math.floor(Date.now() / 1000) - 120,
    exp: Math.floor(Date.now() / 1000) - 60,
    jti: crypto.randomUUID(),
  };
  const expired = await request("/api/check-in", {
    method: "POST",
    cookie: scannerCookie,
    body: JSON.stringify({ token: createToken(expiredClaims) }),
  });
  assert.equal(expired.status, 401);

  const attendance = await request("/api/attendance", { cookie: scannerCookie });
  assert.equal(attendance.status, 200);
  assert.equal((await attendance.json()).records.length, 1);

  const persistedState = JSON.parse(
    await fs.readFile(path.join(dataDirectory, "attendance.json"), "utf8"),
  );
  assert.equal(persistedState.attendance.length, 1);
  assert.ok(persistedState.usedTokens[claims.jti]);
});

test("Vercel demo sessions are signed and accepted across function instances", async () => {
  const loginResponse = await fetch(`${vercelUrls[0]}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "student",
      password: "test-attendee-password",
    }),
  });
  assert.equal(loginResponse.status, 200);
  const login = await loginResponse.json();
  assert.equal(login.demoMode, true);

  const cookie = loginResponse.headers.get("set-cookie")?.split(";")[0];
  assert.match(loginResponse.headers.get("set-cookie"), /Secure/);
  const sessionResponse = await fetch(`${vercelUrls[1]}/api/me`, {
    headers: { Cookie: cookie },
  });
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  assert.equal(session.demoMode, true);
  assert.equal(session.user.role, "attendee");

  await assert.rejects(fs.access(path.join(dataDirectory, "signing.key")));
});
