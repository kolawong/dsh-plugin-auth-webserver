/**
 * dsh-plugin-auth-webserver
 *
 * DeepSeek Harness Cordis plugin providing an auth-gated replacement for the
 * stock web transport (`@deepseek-ai/dsh-host-webserver`):
 * 1. A bilingual DeepSeek-themed web login page with HMAC cookie sessions
 * 2. Fallback HTTP Basic Auth for CLI / API clients
 * 3. WebSocket upgrade token verification
 * 4. crypto.randomUUID polyfill for non-HTTPS / raw-IP web clients
 * 5. Remote-IP Host/Origin normalization for privileged RPC endpoints
 *    (authenticated sessions only - never while authentication is disabled,
 *    so the stock loopback Host fence keeps defending DNS rebinding)
 * 6. Auth settings APIs consumed by the Web UI settings card
 * 7. Secure-by-default boot guard (QVD-2026-57410 class): serving on a
 *    non-loopback interface with an empty password generates a strong random
 *    password instead of leaving the privileged /api RPC surface open
 * 8. Per-IP failed-login throttling and constant-time credential compares
 *
 * Installed as a `dsh.bundle`: the shipped cordis.patch.yml disables the
 * in-box `webserver` row and inserts this plugin as `webserver-auth`. It
 * provides the same `webServer` service and registration API as the stock
 * server, so route owners (frontend dist, client modules, ...) compose
 * unchanged. Runtime credential updates persist to a plugin-owned state file
 * under `$DSH_HOME/plugins/dsh-plugin-auth-webserver/state.json` — never into
 * the user's cordis.patch.yml.
 *
 * @license MIT
 */

import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";

const COOKIE_NAME = "dsh_auth_token";
/** Session lifetime: 30 days, in seconds (cookie) and milliseconds (verify). */
const TOKEN_MAX_AGE_SECONDS = 30 * 24 * 3600;
const TOKEN_MAX_AGE_MS = TOKEN_MAX_AGE_SECONDS * 1000;
/** Plugin-owned state directory under the DeepSeek Harness home. */
const STATE_DIR_SEGMENTS = ["plugins", "dsh-plugin-auth-webserver"];
/** Failed-login throttling: consecutive failures (per client IP) before lockout. */
const LOGIN_MAX_FAILURES = 5;
/** Failed-login lockout base delay, doubling per extra failure. */
const LOGIN_LOCKOUT_BASE_MS = 15 * 1000;
/** Failed-login lockout ceiling. */
const LOGIN_LOCKOUT_CAP_MS = 15 * 60 * 1000;

export const name = "auth-webserver";

/**
 * Resolve the DeepSeek Harness home with the same precedence the harness
 * itself uses: `$DSH_HOME` (a blank value counts as unset), else `~/.dsh`.
 * @returns the normalized absolute home path.
 */
function resolveAuthHome() {
  const env = process.env.DSH_HOME;
  if (env !== undefined && env.trim().length > 0) {
    const path = env.trim();
    if (path === "~") return homedir();
    if (path.startsWith("~/") || path.startsWith("~\\")) return join(homedir(), path.slice(2));
    return resolve(path);
  }
  return join(homedir(), ".dsh");
}

function stateDir() {
  return join(resolveAuthHome(), ...STATE_DIR_SEGMENTS);
}

/** Server-side copy, per language. */
const MESSAGES = {
  zh: {
    methodNotAllowed: "方法不允许",
    badCredentials: "用户名或密码错误",
    authRequired: "需要身份验证",
    tooManyAttempts: "登录尝试过于频繁，请稍后再试",
    remoteAuthRequired: "监听非本机回环地址时不能关闭密码保护",
  },
  en: {
    methodNotAllowed: "Method not allowed",
    badCredentials: "Invalid username or password",
    authRequired: "Authentication required",
    tooManyAttempts: "Too many failed attempts; please try again later",
    remoteAuthRequired: "Cannot disable password protection while listening on a non-loopback interface",
  },
};

/**
 * Pick the request language: an explicit `?lang=` wins, then the
 * Accept-Language header. Unmatched or absent preferences fall back to
 * Simplified Chinese (the harness's own fallback locale).
 */
function pickLang(req) {
  const query = new URL(req.url ?? "/", "http://x").searchParams.get("lang");
  if (query === "zh" || query === "en") return query;
  const accept = (req.headers["accept-language"] ?? "").trim().toLowerCase();
  if (accept.startsWith("zh")) return "zh";
  if (accept.startsWith("en")) return "en";
  return "zh";
}

function msg(lang, key) {
  return (MESSAGES[lang] ?? MESSAGES.zh)[key] ?? key;
}

/**
 * Constant-time string comparison: both sides are hashed to fixed-length
 * digests first, so timingSafeEqual never throws on a length mismatch and
 * no length information leaks through comparison timing.
 */
function safeEqual(a, b) {
  const ha = createHash("sha256").update(`${a}`).digest();
  const hb = createHash("sha256").update(`${b}`).digest();
  return timingSafeEqual(ha, hb);
}

/** Login page copy, per language. */
const LOGIN_COPY = {
  zh: {
    lang: "zh-CN",
    subtitle: "远程安全访问认证 · Web Authentication",
    usernameLabel: "用户名",
    usernamePlaceholder: "请输入用户名",
    passwordLabel: "访问密码",
    passwordPlaceholder: "请输入访问密码",
    toggleTitle: "显示/隐藏密码",
    errorMsg: "用户名或密码错误",
    submit: "登 录",
    verifying: "正在验证...",
    success: "登录成功，正在进入...",
    networkError: "网络请求失败，请稍后重试",
  },
  en: {
    lang: "en",
    subtitle: "Secure remote access · Web Authentication",
    usernameLabel: "Username",
    usernamePlaceholder: "Enter username",
    passwordLabel: "Password",
    passwordPlaceholder: "Enter password",
    toggleTitle: "Show/hide password",
    errorMsg: "Invalid username or password",
    submit: "Sign in",
    verifying: "Verifying...",
    success: "Signed in, entering...",
    networkError: "Network error, please try again",
  },
};

export class AuthWebServer extends Service {
  config;
  static Config = z.object({
    host: z.union([z.const("127.0.0.1"), z.const("0.0.0.0")]).default("0.0.0.0"),
    port: z.natural().max(65535).default(3080),
    username: z.string().default("admin"),
    // role('secret'): the settings layer redacts this field out of every
    // settings.describe response and writes it through the secret slot
    // instead - the credential must never ride a settings read over the wire.
    password: z.string().default("").role("secret"),
    realm: z.string().default("DeepSeek Harness Authentication"),
  });
  static { this.Config.meta.volatile = true; }

  exact = new Map();
  prefixes = new Map();
  upgrades = new Map();
  upgradedSockets = new Set();
  /** Per-IP failed-login counters backing the brute-force throttle. */
  loginFailures = new Map();
  indexTaps = [];
  fallback;
  server;
  listenedPort;
  secret;
  /** Earliest token issue time still accepted; every session issued before a logout is revoked. */
  invalidBefore = 0;

  constructor(ctx, config) {
    ctx.inject(["settings"], (sctx) => {
      try {
        if (typeof sctx.settings?.register === "function") {
          sctx.settings.register("auth-webserver", AuthWebServer.Config);
        }
      } catch (e) {
        ctx.logger?.warn?.("[AuthWebServer] Settings registration:", e);
      }
    });

    ctx.inject(["connection"], (cctx) => {
      const conn = cctx.connection;
      if (conn) {
        const origAuthIndex = conn.authorizeIndex?.bind(conn);
        conn.authorizeIndex = (req, res) => {
          if (this.checkAuth(req)) return true;
          return origAuthIndex ? origAuthIndex(req, res) : false;
        };

        const origRejection = conn.requestRejection?.bind(conn);
        conn.requestRejection = (req) => {
          if (this.checkAuth(req)) return undefined;
          return origRejection ? origRejection(req) : 401;
        };

        if (conn.browserAuth) {
          const origIsAuth = conn.browserAuth.isAuthenticated?.bind(conn.browserAuth);
          conn.browserAuth.isAuthenticated = (req) => {
            if (this.checkAuth(req)) return true;
            return origIsAuth ? origIsAuth(req) : false;
          };
          const origAuthInd = conn.browserAuth.authorizeIndex?.bind(conn.browserAuth);
          conn.browserAuth.authorizeIndex = (req, res) => {
            if (this.checkAuth(req)) return true;
            return origAuthInd ? origAuthInd(req, res) : false;
          };
        }
      }
    });

    super(ctx, "webServer");
    this.config = config;
    this.loadState();
    this.initSecret();
    this.ensureAuthEnabled();

    // Register Auth Settings & Login APIs
    this.register({
      kind: "exact",
      path: "/api/auth.login",
      handler: async (req, res) => {
        const lang = pickLang(req);
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ ok: false, error: msg(lang, "methodNotAllowed") }));
          return;
        }
        // Brute-force throttle: this endpoint is public and pre-authentication.
        const waitMs = this.throttleRemainingMs(req);
        if (waitMs > 0) {
          res.writeHead(429, {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "Retry-After": String(Math.max(1, Math.ceil(waitMs / 1000))),
          });
          res.end(JSON.stringify({ ok: false, error: msg(lang, "tooManyAttempts") }));
          return;
        }
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
          try {
            const data = JSON.parse(body || "{}");
            const expectedUser = this.effectiveUsername;
            const expectedPass = this.effectivePassword;

            if (!expectedPass || (safeEqual(data.username ?? "", expectedUser) && safeEqual(data.password ?? "", expectedPass))) {
              this.recordLoginSuccess(req);
              const token = this.generateToken(expectedUser, expectedPass);
              res.writeHead(200, {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TOKEN_MAX_AGE_SECONDS}`,
              });
              res.end(JSON.stringify({ ok: true, username: expectedUser }));
            } else {
              this.recordLoginFailure(req);
              res.writeHead(401, {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
              });
              res.end(JSON.stringify({ ok: false, error: msg(lang, "badCredentials") }));
            }
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
            res.end(JSON.stringify({ ok: false, error: err.message }));
          }
        });
      },
    });

    this.register({
      kind: "exact",
      path: "/api/auth.logout",
      handler: async (req, res) => {
        // Revoke every previously issued session token server-side, so a
        // client that keeps a stale cookie cannot re-enter after logout.
        this.invalidBefore = Date.now();
        this.saveState();
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
        });
        res.end(JSON.stringify({ ok: true }));
      },
    });

    this.register({
      kind: "exact",
      path: "/api/auth.get",
      handler: async (req, res) => {
        // Never echo the password (config, state, or env) back over the wire:
        // an authenticated session has no business reading the shared secret.
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        res.end(JSON.stringify({
          ok: true,
          username: this.effectiveUsername,
          realm: this.config.realm || "DeepSeek Harness Authentication",
          authEnabled: this.authEnabled,
          loopbackOnly: this.loopbackOnly,
        }));
      },
    });

    this.register({
      kind: "exact",
      path: "/api/auth.update",
      handler: async (req, res) => {
        const lang = pickLang(req);
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ ok: false, error: msg(lang, "methodNotAllowed") }));
          return;
        }
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
          try {
            const data = JSON.parse(body);
            // Refuse to disable password protection while serving on a
            // non-loopback interface: unauthenticated remote access to the
            // privileged /api RPC surface is the QVD-2026-57410 exposure.
            if (data.password !== undefined && String(data.password) === "" && !this.loopbackOnly) {
              res.writeHead(400, {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
              });
              res.end(JSON.stringify({ ok: false, error: msg(lang, "remoteAuthRequired") }));
              return;
            }
            if (data.username !== undefined) this.config.username = String(data.username);
            if (data.password !== undefined) this.config.password = String(data.password);
            if (data.realm !== undefined) this.config.realm = String(data.realm);

            // Persist to the plugin-owned state file under $DSH_HOME.
            this.saveState();

            // Also refresh the cookie for the current admin session, minted
            // from the effective credentials so env overrides stay valid.
            const token = this.generateToken(this.effectiveUsername, this.effectivePassword);
            res.writeHead(200, {
              "Content-Type": "application/json; charset=utf-8",
              "Cache-Control": "no-store",
              "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TOKEN_MAX_AGE_SECONDS}`,
            });
            res.end(JSON.stringify({
              ok: true,
              username: this.config.username,
              realm: this.config.realm,
            }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
            res.end(JSON.stringify({ ok: false, error: err.message }));
          }
        });
      },
    });
  }

  /**
   * Apply persisted runtime updates (the settings card) on top of the row
   * config. Environment overrides (DSH_AUTH_USER / DSH_AUTH_PASS) still win at
   * request time and are never written here.
   */
  loadState() {
    let state;
    try {
      const raw = readFileSync(join(stateDir(), "state.json"), "utf8");
      state = JSON.parse(raw);
    } catch {
      return;
    }
    if (state === null || typeof state !== "object") return;
    if (typeof state.username === "string") this.config.username = state.username;
    if (typeof state.password === "string") this.config.password = state.password;
    if (typeof state.realm === "string") this.config.realm = state.realm;
    if (typeof state.logoutAt === "number") this.invalidBefore = state.logoutAt;
  }

  /** Persist the credential overrides made through the settings card. */
  saveState() {
    try {
      const dir = stateDir();
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "state.json"), JSON.stringify({
        username: this.config.username ?? "admin",
        password: this.config.password ?? "",
        realm: this.config.realm ?? "DeepSeek Harness Authentication",
        ...(this.invalidBefore > 0 ? { logoutAt: this.invalidBefore } : {}),
      }, null, 2), { encoding: "utf8", mode: 0o600 });
    } catch (e) {
      this.ctx.logger.warn("Failed to persist auth state:", e);
    }
  }

  initSecret() {
    try {
      const dir = stateDir();
      const secretFile = join(dir, ".secret");
      if (existsSync(secretFile)) {
        this.secret = readFileSync(secretFile, "utf8").trim();
      } else {
        this.secret = randomBytes(32).toString("hex");
        mkdirSync(dir, { recursive: true });
        writeFileSync(secretFile, this.secret, { encoding: "utf8", mode: 0o600 });
      }
    } catch {
      // Ephemeral secret: sessions do not survive a restart, but the server
      // still boots wherever the home is not writable.
      this.secret = randomBytes(32).toString("hex");
    }
  }

  generateToken(user, pass) {
    const now = Date.now();
    const sig = createHmac("sha256", this.secret).update(`${user}:${pass}:${now}`).digest("hex");
    return `${now}.${sig}`;
  }

  verifyToken(token, expectedUser, expectedPass) {
    if (!token || typeof token !== "string") return false;
    const parts = token.split(".");
    if (parts.length !== 2) return false;
    const [tsStr, sig] = parts;
    const ts = parseInt(tsStr, 10);
    if (isNaN(ts) || Date.now() - ts > TOKEN_MAX_AGE_MS || ts > Date.now() + 60000) {
      return false;
    }
    // Sessions issued before the last logout are revoked.
    if (ts < this.invalidBefore) {
      return false;
    }
    const expectedSig = createHmac("sha256", this.secret).update(`${expectedUser}:${expectedPass}:${ts}`).digest("hex");
    try {
      return timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expectedSig, "hex"));
    } catch {
      return false;
    }
  }

  get port() {
    return this.listenedPort;
  }

  get host() {
    return this.config.host;
  }

  /** Effective credentials: environment overrides win over config/state. */
  get effectiveUsername() {
    return process.env.DSH_AUTH_USER || this.config.username || "admin";
  }

  get effectivePassword() {
    return process.env.DSH_AUTH_PASS || this.config.password || "";
  }

  /** Whether a password is in force (env, config, or generated). */
  get authEnabled() {
    return this.effectivePassword.length > 0;
  }

  /** Whether the server binds the loopback interface only. */
  get loopbackOnly() {
    return this.config.host === "127.0.0.1";
  }

  clientIp(req) {
    return req.socket?.remoteAddress ?? "unknown";
  }

  /** Milliseconds the client IP stays locked out; 0 when not throttled. */
  throttleRemainingMs(req) {
    const entry = this.loginFailures.get(this.clientIp(req));
    if (entry === undefined) return 0;
    return Math.max(0, entry.lockedUntil - Date.now());
  }

  recordLoginSuccess(req) {
    this.loginFailures.delete(this.clientIp(req));
  }

  recordLoginFailure(req) {
    const ip = this.clientIp(req);
    const now = Date.now();
    const fails = (this.loginFailures.get(ip)?.fails ?? 0) + 1;
    const lockout = fails >= LOGIN_MAX_FAILURES
      ? Math.min(LOGIN_LOCKOUT_BASE_MS * 2 ** (fails - LOGIN_MAX_FAILURES), LOGIN_LOCKOUT_CAP_MS)
      : 0;
    this.loginFailures.set(ip, { fails, lockedUntil: lockout > 0 ? now + lockout : 0 });
    // Bound the table: drop expired entries when it grows large.
    if (this.loginFailures.size > 10000) {
      for (const [key, entry] of this.loginFailures) {
        if (entry.lockedUntil <= now) this.loginFailures.delete(key);
      }
    }
  }

  /**
   * Secure-by-default guard (QVD-2026-57410 class): serving on a non-loopback
   * interface with authentication disabled leaves the privileged /api RPC
   * surface protected only by the stock Host-header loopback fence, which is
   * not an auth layer. Generate a strong random password instead, persist it,
   * and surface it once so the deployment stays both reachable and closed.
   */
  ensureAuthEnabled() {
    if (this.authEnabled || this.loopbackOnly) return;
    const generated = randomBytes(24).toString("base64url");
    this.config.password = generated;
    this.saveState();
    const banner = [
      "[AuthWebServer] SECURITY: authentication was disabled (empty password) while binding 0.0.0.0.",
      "That combination exposes the unauthenticated /api RPC surface (QVD-2026-57410): the stock Host-header loopback fence is not an auth layer, and remote access is exactly what this plugin's Host normalization would then launder.",
      `A random password has been generated and persisted to ${join(stateDir(), "state.json")} (mode 0600):`,
      `  username: ${this.effectiveUsername}`,
      `  password: ${generated}`,
      "Set `password` in your profile config or DSH_AUTH_PASS to choose your own; bind 127.0.0.1 if you truly want no login.",
    ].join("\n");
    console.log(banner);
    try {
      this.ctx.logger?.warn?.(banner);
    } catch {}
  }

  register(route) {
    const table = route.kind === "exact" ? this.exact : this.prefixes;
    if (table.has(route.path)) {
      throw new Error(`webserver: duplicate ${route.kind} route "${route.path}"`);
    }
    table.set(route.path, route);
    return () => {
      table.delete(route.path);
    };
  }

  registerUpgrade(route) {
    if (this.upgrades.has(route.path)) {
      throw new Error(`webserver: duplicate upgrade route "${route.path}"`);
    }
    this.upgrades.set(route.path, route);
    return () => {
      this.upgrades.delete(route.path);
    };
  }

  registerFallback(handler) {
    if (this.fallback !== undefined) {
      throw new Error("webserver: fallback already registered");
    }
    this.fallback = handler;
    return () => {
      this.fallback = undefined;
    };
  }

  tapIndex(transform) { console.log('[AuthWebServer] tapIndex called, total taps:', this.indexTaps.length + 1);
    this.indexTaps.push(transform);
    return () => {
      const at = this.indexTaps.indexOf(transform);
      if (at !== -1) this.indexTaps.splice(at, 1);
    };
  }

  parseCookies(req) {
    const header = req.headers.cookie;
    if (!header) return {};
    const cookies = {};
    for (const pair of header.split(";")) {
      const idx = pair.indexOf("=");
      if (idx !== -1) {
        const key = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        cookies[key] = decodeURIComponent(val);
      }
    }
    return cookies;
  }

  checkAuth(req) {
    const expectedUser = this.effectiveUsername;
    const expectedPass = this.effectivePassword;

    if (!expectedPass) {
      return true;
    }

    // 1. Cookie session
    const cookies = this.parseCookies(req);
    if (cookies[COOKIE_NAME] && this.verifyToken(cookies[COOKIE_NAME], expectedUser, expectedPass)) {
      return true;
    }

    // 2. HTTP Basic Authorization header — for CLI / API clients ONLY.
    // Browsers (Origin or Sec-Fetch-* headers present) must use the cookie
    // session: a browser with cached Basic credentials would otherwise
    // re-authenticate silently on every request, making logout impossible.
    const auth = req.headers["authorization"];
    const isBrowser = req.headers.origin !== undefined || req.headers["sec-fetch-site"] !== undefined;
    if (!isBrowser && auth && auth.startsWith("Basic ")) {
      // The brute-force throttle covers credential attempts on this path too.
      if (this.throttleRemainingMs(req) > 0) return false;
      try {
        const b64 = auth.slice(6).trim();
        const decoded = Buffer.from(b64, "base64").toString("utf-8");
        const idx = decoded.indexOf(":");
        if (idx !== -1) {
          const user = decoded.slice(0, idx);
          const pass = decoded.slice(idx + 1);
          if (safeEqual(user, expectedUser) && safeEqual(pass, expectedPass)) {
            this.recordLoginSuccess(req);
            return true;
          }
          this.recordLoginFailure(req);
          return false;
        }
      } catch {}
    }

    return false;
  }

  applySecurityHeaders(req) {
    // The Host/Origin rewrite vouches for an authenticated session on a
    // non-loopback serving address. With authentication disabled it would
    // instead launder unauthenticated requests - notably DNS-rebound browser
    // requests (Host: attacker.example) - past the stock loopback Host fence
    // (QVD-2026-57410), so it must never run without credentials in force.
    if (!this.authEnabled) return;
    const port = this.listenedPort || 3080;
    if (req.headers.host && !req.headers.host.startsWith("127.0.0.1") && !req.headers.host.startsWith("localhost")) {
      req.headers["x-forwarded-host"] = req.headers.host;
      req.headers.host = `127.0.0.1:${port}`;
    }
    if (req.headers.origin && !req.headers.origin.includes("127.0.0.1") && !req.headers.origin.includes("localhost")) {
      req.headers["x-forwarded-origin"] = req.headers.origin;
      req.headers.origin = `http://127.0.0.1:${port}`;
    }
  }

  renderLoginPage(res, lang) {
    const copy = LOGIN_COPY[lang] ?? LOGIN_COPY.zh;
    const html = `<!DOCTYPE html>
<html lang="${copy.lang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DeepSeek Harness - ${copy.subtitle}</title>
  <style>
    :root {
      --bg-base: #0a0d14;
      --bg-card: rgba(18, 24, 38, 0.88);
      --border-card: rgba(77, 107, 254, 0.22);
      --text-primary: #f0f4fc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent: #4d6bfe;
      --accent-gradient: linear-gradient(135deg, #4d6bfe 0%, #2563eb 100%);
      --input-bg: rgba(14, 18, 28, 0.9);
      --input-border: rgba(255, 255, 255, 0.12);
      --input-border-focus: #4d6bfe;
      --error-bg: rgba(239, 68, 68, 0.15);
      --error-border: rgba(239, 68, 68, 0.35);
      --error-text: #f87171;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      background-color: var(--bg-base);
      background-image:
        radial-gradient(circle at 50% 12%, rgba(77, 107, 254, 0.22) 0%, transparent 60%),
        radial-gradient(circle at 85% 85%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
        radial-gradient(circle at 15% 75%, rgba(99, 102, 241, 0.08) 0%, transparent 50%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-primary);
      padding: 20px;
    }
    .background-grid {
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(to right, rgba(255, 255, 255, 0.025) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.025) 1px, transparent 1px);
      background-size: 36px 36px;
      mask-image: radial-gradient(circle at 50% 50%, black 30%, transparent 80%);
      -webkit-mask-image: radial-gradient(circle at 50% 50%, black 30%, transparent 80%);
      pointer-events: none;
    }
    .login-container {
      position: relative;
      z-index: 1;
      width: 100%;
      max-width: 400px;
      background: var(--bg-card);
      backdrop-filter: blur(28px);
      -webkit-backdrop-filter: blur(28px);
      border: 1px solid var(--border-card);
      border-radius: 20px;
      padding: 38px 32px;
      box-shadow:
        0 24px 60px rgba(0, 0, 0, 0.6),
        0 0 50px rgba(77, 107, 254, 0.12);
      animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(14px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .brand-header {
      text-align: center;
      margin-bottom: 28px;
    }
    .logo-badge {
      width: 60px;
      height: 60px;
      margin: 0 auto 16px;
      background: linear-gradient(135deg, rgba(77, 107, 254, 0.25) 0%, rgba(37, 99, 235, 0.12) 100%);
      border: 1px solid rgba(77, 107, 254, 0.35);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 24px rgba(77, 107, 254, 0.2);
    }
    .logo-badge svg {
      width: 32px;
      height: 32px;
      color: #60a5fa;
    }
    .title {
      font-size: 21px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text-primary);
      margin-bottom: 6px;
    }
    .subtitle {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .form-group {
      margin-bottom: 18px;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }
    .input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-icon {
      position: absolute;
      left: 14px;
      width: 18px;
      height: 18px;
      color: var(--text-muted);
      pointer-events: none;
      transition: color 0.2s;
    }
    .form-input {
      width: 100%;
      height: 44px;
      padding: 0 40px 0 42px;
      background: var(--input-bg);
      border: 1px solid var(--input-border);
      border-radius: 10px;
      color: var(--text-primary);
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .form-input:focus {
      border-color: var(--input-border-focus);
      box-shadow: 0 0 0 3px rgba(77, 107, 254, 0.25);
      background: rgba(18, 24, 38, 0.95);
    }
    .form-input:focus ~ .input-icon {
      color: var(--accent);
    }
    .toggle-password {
      position: absolute;
      right: 12px;
      background: none;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color 0.2s;
    }
    .toggle-password:hover {
      color: var(--text-secondary);
    }
    .toggle-password svg {
      width: 18px;
      height: 18px;
    }
    .error-box {
      display: none;
      padding: 10px 14px;
      background: var(--error-bg);
      border: 1px solid var(--error-border);
      border-radius: 8px;
      color: var(--error-text);
      font-size: 13px;
      margin-bottom: 18px;
      align-items: center;
      gap: 8px;
      animation: shake 0.4s ease;
    }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }
    .error-box svg {
      flex-shrink: 0;
      width: 16px;
      height: 16px;
    }
    .submit-btn {
      width: 100%;
      height: 44px;
      background: var(--accent-gradient);
      border: none;
      border-radius: 10px;
      color: #ffffff;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 14px rgba(77, 107, 254, 0.35);
      transition: all 0.2s ease;
      margin-top: 6px;
    }
    .submit-btn:hover {
      opacity: 0.95;
      box-shadow: 0 6px 20px rgba(77, 107, 254, 0.45);
      transform: translateY(-1px);
    }
    .submit-btn:active {
      transform: translateY(0);
    }
    .submit-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .spinner {
      display: none;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .footer-note {
      text-align: center;
      margin-top: 24px;
      font-size: 12px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="background-grid"></div>
  <div class="login-container">
    <div class="brand-header">
      <div class="logo-badge">
        <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <h1 class="title">DeepSeek Harness</h1>
      <p class="subtitle">${copy.subtitle}</p>
    </div>

    <div id="errorBox" class="error-box">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <span id="errorMsg">${copy.errorMsg}</span>
    </div>

    <form id="loginForm" onsubmit="return handleLogin(event)">
      <div class="form-group">
        <label class="form-label" for="username">${copy.usernameLabel}</label>
        <div class="input-wrapper">
          <input type="text" id="username" class="form-input" placeholder="${copy.usernamePlaceholder}" required autofocus autocomplete="username">
          <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
          </svg>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label" for="password">${copy.passwordLabel}</label>
        <div class="input-wrapper">
          <input type="password" id="password" class="form-input" placeholder="${copy.passwordPlaceholder}" required autocomplete="current-password">
          <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
          </svg>
          <button type="button" class="toggle-password" id="togglePassword" onclick="togglePasswordVisibility()" title="${copy.toggleTitle}">
            <svg id="eyeIcon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
            </svg>
          </button>
        </div>
      </div>

      <button type="submit" id="submitBtn" class="submit-btn">
        <span class="spinner" id="spinner"></span>
        <span id="btnText">${copy.submit}</span>
      </button>
    </form>

    <div class="footer-note">
      DeepSeek Harness · Secure Web Gateway
    </div>
  </div>

  <script>
    function togglePasswordVisibility() {
      const pwdInput = document.getElementById("password");
      const eyeIcon = document.getElementById("eyeIcon");
      if (pwdInput.type === "password") {
        pwdInput.type = "text";
        eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/>';
      } else {
        pwdInput.type = "password";
        eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>';
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value;
      const errorBox = document.getElementById("errorBox");
      const errorMsg = document.getElementById("errorMsg");
      const submitBtn = document.getElementById("submitBtn");
      const spinner = document.getElementById("spinner");
      const btnText = document.getElementById("btnText");

      errorBox.style.display = "none";
      submitBtn.disabled = true;
      spinner.style.display = "inline-block";
      btnText.textContent = "${copy.verifying}";

      try {
        const res = await fetch("/api/auth.login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.ok) {
          btnText.textContent = "${copy.success}";
          setTimeout(() => {
            window.location.reload();
          }, 300);
        } else {
          submitBtn.disabled = false;
          spinner.style.display = "none";
          btnText.textContent = "${copy.submit}";
          errorMsg.textContent = data.error || "${copy.errorMsg}";
          errorBox.style.display = "flex";
          document.getElementById("password").focus();
        }
      } catch (err) {
        submitBtn.disabled = false;
        spinner.style.display = "none";
        btnText.textContent = "${copy.submit}";
        errorMsg.textContent = "${copy.networkError}";
        errorBox.style.display = "flex";
      }
      return false;
    }
  </script>
</body>
</html>`;

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    res.end(html);
  }

  async [Service.init]() {
    const handle = async (req, res) => {
      const rawPath = new URL(req.url ?? "/", "http://x").pathname;

      // Public routes: login endpoint, PWA webmanifest, favicons, robots.txt, plugin static assets
      const isPublicPath =
        rawPath === "/api/auth.login" ||
        rawPath === "/manifest.webmanifest" ||
        rawPath === "/manifest.json" ||
        rawPath === "/favicon.ico" ||
        rawPath === "/favicon.svg" ||
        rawPath === "/apple-touch-icon.png" ||
        rawPath === "/robots.txt" ||
        rawPath.startsWith("/plugins/");

      if (isPublicPath) {
        const route = this.match(rawPath);
        if (route !== undefined) {
          await route.handler(req, res);
          return;
        }
        if (this.fallback !== undefined) {
          await this.fallback(req, res);
          return;
        }
      }

      if (!this.checkAuth(req)) {
        const accept = req.headers.accept || "";
        const isHtmlRequest = rawPath === "/" || rawPath === "/index.html" || accept.includes("text/html");

        // Browsers get the themed login page instead of a native popup.
        if (isHtmlRequest && req.method === "GET") {
          this.renderLoginPage(res, pickLang(req));
          return;
        }

        // API / CLI clients get a JSON 401. No WWW-Authenticate header, so
        // browsers never fall back to their native credential dialog.
        res.writeHead(401, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        res.end(JSON.stringify({ ok: false, error: msg(pickLang(req), "authRequired") }));
        return;
      }

      this.applySecurityHeaders(req);

      const route = this.match(rawPath);
      if (route !== undefined) {
        await route.handler(req, res);
        return;
      }
      const fallback = this.fallback;
      if (fallback === undefined) {
        res.writeHead(404);
        res.end();
        return;
      }
      await fallback(req, res);
    };

    this.server = createServer((req, res) => {
      handle(req, res).catch((err) => {
        console.error("[AuthWebServer handle error]", err); this.ctx.logger.warn(err instanceof Error ? err : new Error(String(err)));
        if (res.headersSent) {
          res.destroy();
          return;
        }
        res.writeHead(400);
        res.end();
      });
    });

    this.server.on("upgrade", (req, socket, head) => {
      const onError = (error) => {
        this.ctx.logger.warn(error);
        socket.destroy();
      };
      socket.on("error", onError);
      socket.once("close", () => {
        socket.off("error", onError);
        this.upgradedSockets.delete(socket);
      });

      if (!this.checkAuth(req)) {
        socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        socket.destroy();
        return;
      }

      this.applySecurityHeaders(req);

      let route;
      try {
        route = this.upgrades.get(new URL(req.url ?? "/", "http://x").pathname);
      } catch (error) {
        this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
        socket.destroy();
        return;
      }
      if (route === undefined) {
        socket.destroy();
        return;
      }
      this.upgradedSockets.add(socket);
      try {
        Promise.resolve(route.handler(req, socket, head)).catch((error) => {
          this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
          socket.destroy();
        });
      } catch (error) {
        this.ctx.logger.warn(error instanceof Error ? error : new Error(String(error)));
        socket.destroy();
      }
    });

    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.config.port, this.config.host, () => {
        this.server.off("error", reject);
        this.server.on("error", (err) => {
          this.ctx.logger.error(err);
        });
        this.listenedPort = this.server.address().port;
        resolve();
      });
    });

    this.ctx.effect(() => async () => {
      const serverClosed = new Promise((resolve) => {
        this.server.close(() => {
          resolve();
        });
      });
      this.server.closeAllConnections();
      const upgradedClosed = [...this.upgradedSockets].map((socket) => new Promise((resolve) => {
        socket.once("close", () => {
          resolve();
        });
        socket.destroy();
      }));
      await Promise.all([serverClosed, ...upgradedClosed]);
    }, "webServer.listen");
  }

  match(pathname) {
    const exact = this.exact.get(pathname);
    if (exact !== undefined) return exact;
    let best;
    for (const [prefix, route] of this.prefixes) {
      if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
      if (best === undefined || prefix.length > best.path.length) best = route;
    }
    return best;
  }

  collectIndexInjections() {
    const table = [];
    this.ctx.emit("webserver/index-inject", table);
    return table;
  }

  renderIndex(html) {
    return this.applyIndexTaps(renderIndexInjections(html, this.collectIndexInjections()));
  }

  applyIndexTaps(html) {
    let out = html;
    for (const transform of this.indexTaps) out = transform(out);

    // Polyfill crypto.randomUUID for non-HTTPS / IP environments and grant host ownership to authenticated operator
    const polyfill = `<script>
(function() {
  window.__DSH_TRANSPORT__ = Object.assign(window.__DSH_TRANSPORT__ || {}, { ownsHost: true });
  var c = window.crypto || (window.crypto = {});
  if (typeof c.randomUUID !== 'function') {
    c.randomUUID = function() {
      if (typeof c.getRandomValues === 'function') {
        return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, function(ch) {
          return (ch ^ c.getRandomValues(new Uint8Array(1))[0] & 15 >> ch / 4).toString(16);
        });
      }
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(ch) {
        var r = Math.random() * 16 | 0, v = ch === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    };
  }
})();
</script>`;

    if (out.includes('<head>')) {
      out = out.replace('<head>', '<head>' + polyfill);
    } else {
      out = polyfill + out;
    }
    return out;
  }
}

function escapeHtmlAttribute(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function renderRow(row) {
  switch (row.kind) {
    case 'global': {
      const name = JSON.stringify(row.name).replaceAll('<', '\\u003c');
      const value = row.value === undefined
        ? 'undefined'
        : JSON.stringify(row.value).replaceAll('<', '\\u003c');
      return { placement: 'head', markup: `<script>globalThis[${name}] = ${value}</script>` };
    }
    case 'script':
      return { placement: row.placement, markup: `<script>${row.text}</script>` };
    case 'script-src':
      return { placement: row.placement, markup: `<script src="${escapeHtmlAttribute(row.src)}"></script>` };
    case 'style':
      return { placement: 'head', markup: `<style>${row.text}</style>` };
    case 'html':
      return { placement: row.placement, markup: row.html };
    default:
      return { placement: 'head', markup: '' };
  }
}

function splice(html, at, markup) {
  return `${html.slice(0, at)}${markup}${html.slice(at)}`;
}

export function renderIndexInjections(html, rows) {
  let head = '';
  let body = '';
  for (const row of rows) {
    const rendered = renderRow(row);
    if (rendered.placement === 'head') head += rendered.markup;
    else body += rendered.markup;
  }
  let out = html;
  if (head !== '') {
    const open = /<head(?:\s[^>]*)?>/i.exec(out);
    out = open === null ? `${head}${out}` : splice(out, open.index + open[0].length, head);
  }
  if (body !== '') {
    const open = /<body(?:\s[^>]*)?>/i.exec(out);
    out = open === null ? `${out}${body}` : splice(out, open.index + open[0].length, body);
  }
  return out;
}

export const Config = AuthWebServer.Config;
export default AuthWebServer;

