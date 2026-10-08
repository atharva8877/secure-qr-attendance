const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { promisify } = require("node:util");
const QRCode = require("qrcode");

const pbkdf2 = promisify(crypto.pbkdf2);
const ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, ".data"));
const STATE_FILE = path.join(DATA_DIR, "attendance.json");
const PORT = Number(process.env.PORT || 3000);
const IS_VERCEL = process.env.VERCEL === "1";
const TOKEN_LIFETIME_SECONDS = 60;
const SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000;
const EVENT = Object.freeze({
  id: "event-2026-42",
  name: "Campus Tech Fest 2026",
  attendeeIds: new Set(["attendee-001"]),
});

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("PORT must be an integer from 1 to 65535");
}

const demoCredentials = {
  attendee: {
    username: "student",
    password: process.env.ATTENDEE_PASSWORD || "student123",
    role: "attendee",
    id: "attendee-001",
    displayName: "Alex Morgan",
  },
  scanner: {
    username: "staff",
    password: process.env.SCANNER_PASSWORD || "scanner123",
    role: "scanner",
    id: "scanner-001",
    displayName: "Event Staff",
  },
};

const sessions = new Map();
const loginFailures = new Map();
const credentialDigests = new Map();
let dummyCredentialDigest;
let signingKey;
let state = { attendance: [], usedTokens: {} };
let stateQueue = Promise.resolve();
let initialization;

function readOrCreateSigningKey() {
  const fromEnvironment = process.env.QR_HMAC_SECRET;
  if (fromEnvironment) {
    const key = Buffer.from(fromEnvironment, "utf8");
    if (key.length < 32) {
      throw new Error("QR_HMAC_SECRET must be at least 32 UTF-8 bytes");
    }
    return key;
  }
  if (IS_VERCEL) {
    throw new Error("QR_HMAC_SECRET must be set in Vercel environment variables");
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const key = crypto.randomBytes(32);
    fs.writeFileSync(path.join(DATA_DIR, "signing.key"), key, {
      flag: "wx",
      mode: 0o600,
    });
    return key;
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const key = fs.readFileSync(path.join(DATA_DIR, "signing.key"));
    if (key.length !== 32) throw new Error("The stored signing key is invalid");
    return key;
  }
}

function loadState() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    const stored = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    if (
      !stored ||
      !Array.isArray(stored.attendance) ||
      !stored.usedTokens ||
      typeof stored.usedTokens !== "object" ||
      Array.isArray(stored.usedTokens)
    ) {
      throw new Error("Attendance data has an invalid format");
    }
    return stored;
  } catch (error) {
    if (error.code === "ENOENT") return { attendance: [], usedTokens: {} };
    throw error;
  }
}

async function saveState(nextState) {
  if (IS_VERCEL) return;
  const temporaryFile = `${STATE_FILE}.${crypto.randomUUID()}.tmp`;
  try {
    await fs.promises.writeFile(temporaryFile, JSON.stringify(nextState), {
      mode: 0o600,
    });
    await fs.promises.rename(temporaryFile, STATE_FILE);
  } catch (error) {
    await fs.promises.rm(temporaryFile, { force: true });
    throw error;
  }
}

function serializeState(operation) {
  const result = stateQueue.then(operation);
  stateQueue = result.catch(() => {});
  return result;
}

function jsonResponse(response, status, body, extraHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  response.end(JSON.stringify(body));
}

function requestBody(request) {
  if (request.body !== undefined) {
    const body =
      Buffer.isBuffer(request.body) || typeof request.body === "string"
        ? request.body.toString()
        : JSON.stringify(request.body);
    if (Buffer.byteLength(body) > 16_384) {
      return Promise.reject(Object.assign(new Error("Request body is too large"), { status: 413 }));
    }
    try {
      return Promise.resolve(body ? JSON.parse(body) : {});
    } catch {
      return Promise.reject(
        Object.assign(new Error("Request body must be valid JSON"), { status: 400 }),
      );
    }
  }

  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > 16_384) {
        reject(Object.assign(new Error("Request body is too large"), { status: 413 }));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON"), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function cookies(request) {
  return Object.fromEntries(
    (request.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split(/=(.*)/s).slice(0, 2))
      .filter(([name, value]) => name && value !== undefined)
      .map(([name, value]) => [name, decodeURIComponent(value)]),
  );
}

function getSession(request) {
  const sessionId = cookies(request).cns_session;
  if (IS_VERCEL) {
    if (!sessionId) return null;
    const [payloadPart, signaturePart] = sessionId.split(".");
    if (!payloadPart || !signaturePart) return null;
    const expected = crypto
      .createHmac("sha256", signingKey)
      .update(payloadPart)
      .digest();
    let signature;
    let payload;
    try {
      signature = Buffer.from(signaturePart, "base64url");
      payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    } catch {
      return null;
    }
    if (
      signature.length !== expected.length ||
      !crypto.timingSafeEqual(signature, expected) ||
      !payload.user ||
      !Number.isInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000) ||
      !["attendee", "scanner"].includes(payload.user.role)
    ) {
      return null;
    }
    return payload.user;
  }

  const session = sessionId && sessions.get(sessionId);
  if (!session || session.expiresAt <= Date.now()) {
    if (sessionId) sessions.delete(sessionId);
    return null;
  }
  return session.user;
}

function requireRole(request, response, role) {
  const user = getSession(request);
  if (!user) {
    jsonResponse(response, 401, { error: "Please sign in to continue." });
    return null;
  }
  if (user.role !== role) {
    jsonResponse(response, 403, { error: "Your account cannot perform this action." });
    return null;
  }
  return user;
}

function checkSameOrigin(request, response) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    if (new URL(origin).host === request.headers.host) return true;
  } catch {
    // Invalid origins are rejected below.
  }
  jsonResponse(response, 403, { error: "Cross-origin requests are not allowed." });
  return false;
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function createSessionCookie(user) {
  const secure = process.env.NODE_ENV === "production" || IS_VERCEL ? "; Secure" : "";
  let cookieValue;
  if (IS_VERCEL) {
    const payload = encodeBase64Url(
      JSON.stringify({
        user: {
          role: user.role,
          id: user.id,
          displayName: user.displayName,
          username: user.username,
        },
        exp: Math.floor(Date.now() / 1000) + SESSION_LIFETIME_MS / 1000,
      }),
    );
    const signature = crypto
      .createHmac("sha256", signingKey)
      .update(payload)
      .digest("base64url");
    cookieValue = `${payload}.${signature}`;
  } else {
    cookieValue = crypto.randomBytes(32).toString("base64url");
    sessions.set(cookieValue, { user, expiresAt: Date.now() + SESSION_LIFETIME_MS });
  }
  return `cns_session=${cookieValue}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME_MS / 1000}${secure}`;
}

function issueToken(attendeeId) {
  const now = Math.floor(Date.now() / 1000);
  const header = encodeBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = encodeBase64Url(
    JSON.stringify({
      sub: attendeeId,
      event: EVENT.id,
      iat: now,
      exp: now + TOKEN_LIFETIME_SECONDS,
      jti: crypto.randomUUID(),
    }),
  );
  const signingInput = `${header}.${payload}`;
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(signingInput)
    .digest("base64url");
  return `${signingInput}.${signature}`;
}

function verifyToken(token) {
  if (typeof token !== "string" || token.length > 4096) {
    throw Object.assign(new Error("The QR token is invalid."), { status: 400 });
  }
  const segments = token.split(".");
  if (segments.length !== 3 || segments.some((segment) => !segment)) {
    throw Object.assign(new Error("The QR token is invalid."), { status: 400 });
  }

  const [headerPart, payloadPart, signaturePart] = segments;
  let header;
  let claims;
  let signature;
  try {
    header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    signature = Buffer.from(signaturePart, "base64url");
  } catch {
    throw Object.assign(new Error("The QR token is invalid."), { status: 400 });
  }

  const expected = crypto
    .createHmac("sha256", signingKey)
    .update(`${headerPart}.${payloadPart}`)
    .digest();
  if (
    header.alg !== "HS256" ||
    header.typ !== "JWT" ||
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(signature, expected)
  ) {
    throw Object.assign(new Error("The QR signature could not be verified."), { status: 401 });
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    typeof claims.sub !== "string" ||
    typeof claims.event !== "string" ||
    typeof claims.jti !== "string" ||
    !Number.isInteger(claims.iat) ||
    !Number.isInteger(claims.exp) ||
    claims.iat > now + 5 ||
    claims.exp <= now ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > TOKEN_LIFETIME_SECONDS
  ) {
    throw Object.assign(new Error("The QR code has expired or is invalid."), { status: 401 });
  }
  if (claims.event !== EVENT.id) {
    throw Object.assign(new Error("This QR code is for a different event."), { status: 403 });
  }
  if (!EVENT.attendeeIds.has(claims.sub)) {
    throw Object.assign(new Error("This attendee is not enrolled for the event."), { status: 403 });
  }
  return claims;
}

async function handleApi(request, response, url) {
  const { pathname } = url;
  const method = request.method;

  if (method === "GET" && pathname === "/api/me") {
    const user = getSession(request);
    return jsonResponse(response, 200, {
      user: user
        ? { role: user.role, displayName: user.displayName, username: user.username }
        : null,
      event: { id: EVENT.id, name: EVENT.name },
      demoMode: IS_VERCEL,
    });
  }

  if (method === "POST" && pathname === "/api/login") {
    const body = await requestBody(request);
    const username = typeof body.username === "string" ? body.username : "";
    const password = typeof body.password === "string" ? body.password : "";
    const throttleKey = request.socket.remoteAddress || "unknown";
    const failures = loginFailures.get(throttleKey) || { count: 0, windowStarted: Date.now() };
    if (Date.now() - failures.windowStarted > 15 * 60 * 1000) {
      failures.count = 0;
      failures.windowStarted = Date.now();
    }
    if (failures.count >= 10) {
      return jsonResponse(response, 429, { error: "Too many sign-in attempts. Try again later." });
    }

    const account = Object.values(demoCredentials).find((entry) => entry.username === username);
    const salt = account ? account.username : "invalid-account";
    const candidate = await pbkdf2(password, salt, 310_000, 32, "sha256");
    const expected = credentialDigests.get(username) || dummyCredentialDigest;
    if (
      !account ||
      candidate.length !== expected.length ||
      !crypto.timingSafeEqual(candidate, expected)
    ) {
      failures.count += 1;
      loginFailures.set(throttleKey, failures);
      return jsonResponse(response, 401, { error: "Username or password is incorrect." });
    }

    loginFailures.delete(throttleKey);
    const previousSessionId = cookies(request).cns_session;
    if (previousSessionId) sessions.delete(previousSessionId);
    const user = {
      role: account.role,
      id: account.id,
      displayName: account.displayName,
      username: account.username,
    };
    return jsonResponse(
      response,
      200,
      {
        user: { role: user.role, displayName: user.displayName, username: user.username },
        event: { id: EVENT.id, name: EVENT.name },
        demoMode: IS_VERCEL,
      },
      {
        "Set-Cookie": createSessionCookie(user),
      },
    );
  }

  if (method === "POST" && pathname === "/api/logout") {
    const sessionId = cookies(request).cns_session;
    if (sessionId && !IS_VERCEL) sessions.delete(sessionId);
    return jsonResponse(response, 200, { ok: true }, {
      "Set-Cookie": "cns_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    });
  }

  if (method === "GET" && pathname === "/api/qr") {
    const user = requireRole(request, response, "attendee");
    if (!user) return;
    const token = issueToken(user.id);
    const qrCode = await QRCode.toDataURL(token, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: 320,
    });
    return jsonResponse(response, 200, {
      token,
      qrCode,
      expiresAt: Math.floor(Date.now() / 1000) + TOKEN_LIFETIME_SECONDS,
      event: EVENT.name,
    });
  }

  if (method === "POST" && pathname === "/api/check-in") {
    const user = requireRole(request, response, "scanner");
    if (!user) return;
    const body = await requestBody(request);
    let claims;
    try {
      claims = verifyToken(body.token);
    } catch (error) {
      return jsonResponse(response, error.status || 400, { error: error.message });
    }

    return serializeState(async () => {
      const now = Math.floor(Date.now() / 1000);
      for (const [id, expiry] of Object.entries(state.usedTokens)) {
        if (expiry <= now) delete state.usedTokens[id];
      }
      if (state.usedTokens[claims.jti]) {
        return jsonResponse(response, 409, { error: "This QR code has already been scanned." });
      }

      const existing = state.attendance.find(
        (record) => record.eventId === claims.event && record.attendeeId === claims.sub,
      );
      const nextState = {
        attendance: state.attendance.slice(),
        usedTokens: { ...state.usedTokens, [claims.jti]: claims.exp },
      };
      if (existing) {
        await saveState(nextState);
        state = nextState;
        return jsonResponse(response, 409, { error: "This attendee is already checked in." });
      }

      nextState.attendance.push({
        eventId: claims.event,
        attendeeId: claims.sub,
        scannedAt: new Date().toISOString(),
        scannerId: user.id,
      });
      await saveState(nextState);
      state = nextState;
      return jsonResponse(response, 200, {
        ok: true,
        attendee: demoCredentials.attendee.displayName,
        event: EVENT.name,
        checkedInAt: nextState.attendance[nextState.attendance.length - 1].scannedAt,
      });
    });
  }

  if (method === "GET" && pathname === "/api/attendance") {
    const user = requireRole(request, response, "scanner");
    if (!user) return;
    const records = state.attendance
      .filter((record) => record.eventId === EVENT.id)
      .map((record) => ({
        attendee: demoCredentials.attendee.displayName,
        scannedAt: record.scannedAt,
      }));
    return jsonResponse(response, 200, { records });
  }

  return jsonResponse(response, 404, { error: "Endpoint not found." });
}

function serveStatic(request, response, url) {
  const requestedPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const absolutePath = path.resolve(PUBLIC_DIR, `.${requestedPath}`);
  if (!absolutePath.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    response.writeHead(403);
    return response.end("Forbidden");
  }

  fs.readFile(absolutePath, (error, contents) => {
    if (error) {
      response.writeHead(error.code === "ENOENT" ? 404 : 500);
      return response.end(error.code === "ENOENT" ? "Not found" : "Unable to read file");
    }
    const contentTypes = {
      ".css": "text/css; charset=utf-8",
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".svg": "image/svg+xml",
    };
    response.writeHead(200, {
      "Content-Type": contentTypes[path.extname(absolutePath)] || "application/octet-stream",
      "Cache-Control": "no-cache",
    });
    response.end(contents);
  });
}

async function initialize() {
  if (!initialization) {
    initialization = (async () => {
      if (
        IS_VERCEL &&
        (!process.env.ATTENDEE_PASSWORD ||
          !process.env.SCANNER_PASSWORD ||
          process.env.ATTENDEE_PASSWORD === "student123" ||
          process.env.SCANNER_PASSWORD === "scanner123")
      ) {
        throw new Error(
          "Set non-default ATTENDEE_PASSWORD and SCANNER_PASSWORD values in Vercel environment variables",
        );
      }
      signingKey = readOrCreateSigningKey();
      state = IS_VERCEL ? { attendance: [], usedTokens: {} } : loadState();
      for (const account of Object.values(demoCredentials)) {
        credentialDigests.set(
          account.username,
          await pbkdf2(account.password, account.username, 310_000, 32, "sha256"),
        );
      }
      dummyCredentialDigest = await pbkdf2(
        crypto.randomBytes(32),
        "invalid-account",
        310_000,
        32,
        "sha256",
      );
    })();
  }
  return initialization;
}

async function handler(request, response) {
  try {
    await initialize();
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'");
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) {
      if (request.method !== "GET" && !checkSameOrigin(request, response)) return;
      await handleApi(request, response, url);
    } else if (request.method === "GET") {
      serveStatic(request, response, url);
    } else {
      jsonResponse(response, 405, { error: "Method not allowed." });
    }
  } catch (error) {
    console.error("Request failed:", error);
    if (!response.headersSent) {
      jsonResponse(response, error.status || 500, {
        error: error.status ? error.message : "The request could not be completed.",
      });
    } else {
      response.destroy();
    }
  }
}

async function main() {
  await initialize();
  const server = http.createServer(handler);
  server.listen(PORT, () => {
    console.log(`Secure QR attendance is running at http://localhost:${PORT}`);
    if (IS_VERCEL) {
      console.warn("Vercel demo mode is active. Attendance and replay records are temporary.");
    } else if (
      !process.env.ATTENDEE_PASSWORD ||
      !process.env.SCANNER_PASSWORD ||
      !process.env.QR_HMAC_SECRET
    ) {
      console.warn(
        "Demo mode is active. Use the documented demo logins locally; configure all three security environment variables before deployment.",
      );
    }
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error("Startup failed:", error);
    process.exitCode = 1;
  });
} else {
  module.exports = handler;
}
