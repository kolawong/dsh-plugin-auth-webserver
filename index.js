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
    badge: "AGENT = MODEL + HARNESS",
    heroTitle: "一切皆插件",
    heroDesc: "模型是 Agent 的灵魂，Harness 让 Agent 在真实场景中持续工作",
    gatewayStatus: "受保护的网关",
    terminalTitle: "auth@deepseek-harness: ~",
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
    docs: "开发者文档",
  },
  en: {
    lang: "en",
    badge: "AGENT = MODEL + HARNESS",
    heroTitle: "All As Plugins",
    heroDesc: "Models are the soul of Agents; Harness empowers them to work in the real world",
    gatewayStatus: "Protected Gateway",
    terminalTitle: "auth@deepseek-harness: ~",
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
    docs: "Documentation",
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
    const i18nJson = JSON.stringify(LOGIN_COPY);
    const html = `<!DOCTYPE html>
<html lang="${copy.lang}" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DeepSeek Harness - ${copy.heroTitle}</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="icon" href="/favicon.ico" type="image/x-icon">
  <style>
    :root {
      --ds-bg-page: #0a0a0a;
      --ds-color-brand: #6799fe;
      --ds-color-text-primary: #ffffff;
      --ds-color-text-secondary: hsla(0, 0%, 100%, 0.75);
      --ds-color-text-description: hsla(0, 0%, 100%, 0.5);
      --ds-color-text-placeholder: hsla(0, 0%, 100%, 0.3);
      --ds-color-bg-surface: rgba(14, 16, 22, 0.72);
      --ds-color-bg-input: hsla(0, 0%, 100%, 0.05);
      --ds-color-border-input: hsla(0, 0%, 100%, 0.12);
      --ds-color-border-focus: #6799fe;
      --ds-color-border-subtle: hsla(0, 0%, 100%, 0.08);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      background-color: #0a0a0a;
      background-image:
        radial-gradient(ellipse 90% 55% at 50% -10%, rgba(77, 107, 254, 0.22) 0%, rgba(10, 10, 10, 0) 70%),
        radial-gradient(circle at 85% 85%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(circle at 15% 75%, rgba(99, 102, 241, 0.06) 0%, transparent 50%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      position: relative;
      overflow-x: hidden;
      padding: 84px 20px 40px;
    }
    #heroCanvas {
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 1;
      mask-image: radial-gradient(circle at 50% 45%, black 45%, transparent 85%), linear-gradient(to bottom, black 0%, black 80%, transparent 100%);
      -webkit-mask-image: radial-gradient(circle at 50% 45%, black 45%, transparent 85%), linear-gradient(to bottom, black 0%, black 80%, transparent 100%);
    }
    .ds-header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 64px;
      padding: 0 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      z-index: 20;
      background: linear-gradient(to bottom, rgba(10, 10, 10, 0.85) 0%, transparent 100%);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
    }
    .ds-header-inner {
      width: 100%;
      max-width: 1140px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .ds-logo-group {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
      color: #ffffff;
    }
    .ds-badge-wrap {
      display: inline-flex;
      align-items: center;
      border-radius: 8px;
      padding: 1px;
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.75) 0%, rgba(255, 255, 255, 0.08) 35%, rgba(255, 255, 255, 0.04) 65%, rgba(255, 255, 255, 0.5) 100%);
      box-shadow: 0 0 16px rgba(255, 255, 255, 0.08), 0 0 32px rgba(255, 255, 255, 0.04);
    }
    .ds-badge-inner {
      padding: 4px 9px;
      border-radius: 7px;
      background: rgba(0, 0, 0, 0.35);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      font-weight: 500;
      color: rgba(255, 255, 255, 0.95);
      line-height: 1;
    }
    .ds-locale-toggle {
      display: inline-flex;
      align-items: center;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 9999px;
      padding: 2px;
    }
    .ds-locale-btn {
      background: transparent;
      border: none;
      color: rgba(255, 255, 255, 0.45);
      font-size: 12px;
      font-weight: 500;
      padding: 4px 12px;
      border-radius: 9999px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .ds-locale-btn:hover {
      color: rgba(255, 255, 255, 0.85);
    }
    .ds-locale-btn.active {
      background: rgba(255, 255, 255, 0.14);
      color: #ffffff;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    .main-content {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 440px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      animation: heroFadeIn 0.7s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes heroFadeIn {
      from { opacity: 0; transform: translateY(18px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .super-badge-wrap {
      display: inline-flex;
      align-items: center;
      border-radius: 8px;
      padding: 1px;
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.42) 0%, rgba(255, 255, 255, 0.08) 35%, rgba(255, 255, 255, 0.04) 65%, rgba(255, 255, 255, 0.28) 100%);
      box-shadow: 0 0 16px rgba(255, 255, 255, 0.08), 0 0 32px rgba(255, 255, 255, 0.04);
      margin-bottom: 14px;
    }
    .super-badge-inner {
      padding: 5px 12px;
      border-radius: 7px;
      background: rgba(0, 0, 0, 0.35);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      font-weight: 600;
      color: rgba(255, 255, 255, 0.95);
      letter-spacing: 0.06em;
    }
    .hero-title {
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #ffffff;
      margin-bottom: 8px;
      line-height: 1.2;
    }
    .hero-desc {
      font-size: 13px;
      color: rgba(255, 255, 255, 0.5);
      line-height: 1.6;
      margin-bottom: 24px;
      max-width: 380px;
    }
    .terminal-card {
      width: 100%;
      background: rgba(14, 16, 22, 0.72);
      backdrop-filter: blur(28px);
      -webkit-backdrop-filter: blur(28px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      box-shadow:
        0 28px 70px -15px rgba(0, 0, 0, 0.85),
        0 0 0 1px rgba(255, 255, 255, 0.05),
        0 0 45px -10px rgba(77, 107, 254, 0.16);
      overflow: hidden;
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
    .terminal-card:hover {
      border-color: rgba(255, 255, 255, 0.12);
      box-shadow:
        0 32px 80px -15px rgba(0, 0, 0, 0.9),
        0 0 0 1px rgba(255, 255, 255, 0.07),
        0 0 50px -8px rgba(77, 107, 254, 0.22);
    }
    .terminal-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 18px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .traffic-lights {
      display: flex;
      align-items: center;
      gap: 7px;
    }
    .traffic-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    .dot-red { background: #ff5f57; }
    .dot-yellow { background: #febc2e; }
    .dot-green { background: #28c840; }
    .terminal-title {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      color: rgba(255, 255, 255, 0.4);
    }
    .terminal-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: rgba(255, 255, 255, 0.6);
      font-family: ui-monospace, monospace;
    }
    .badge-status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #22c55e;
      box-shadow: 0 0 6px #22c55e;
    }
    .terminal-body {
      padding: 28px 24px 22px;
    }
    .form-group {
      margin-bottom: 18px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: rgba(255, 255, 255, 0.8);
      margin-bottom: 7px;
    }
    .input-wrapper {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-icon {
      position: absolute;
      left: 14px;
      width: 17px;
      height: 17px;
      color: rgba(255, 255, 255, 0.35);
      pointer-events: none;
      transition: color 0.2s;
    }
    .form-input {
      width: 100%;
      height: 44px;
      padding: 0 40px 0 42px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      color: #ffffff;
      font-size: 14px;
      outline: none;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      font-family: inherit;
    }
    .form-input:focus {
      background: rgba(255, 255, 255, 0.08);
      border-color: #6799fe;
      box-shadow: 0 0 0 3px rgba(103, 153, 254, 0.22);
    }
    .form-input:focus ~ .input-icon {
      color: #6799fe;
    }
    .toggle-password {
      position: absolute;
      right: 10px;
      background: none;
      border: none;
      color: rgba(255, 255, 255, 0.4);
      cursor: pointer;
      padding: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 6px;
      transition: color 0.2s;
    }
    .toggle-password:hover {
      color: rgba(255, 255, 255, 0.85);
    }
    .toggle-password svg {
      width: 18px;
      height: 18px;
    }
    .error-box {
      display: none;
      padding: 10px 14px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      color: #fca5a5;
      font-size: 13px;
      margin-bottom: 18px;
      align-items: center;
      gap: 8px;
      animation: shake 0.4s ease;
    }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-5px); }
      40%, 80% { transform: translateX(5px); }
    }
    .error-icon {
      flex-shrink: 0;
      width: 16px;
      height: 16px;
    }
    .ds-btn-primary {
      width: 100%;
      height: 44px;
      background: #ffffff;
      color: #0a0a0a;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3), 0 0 20px rgba(255, 255, 255, 0.15);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      margin-top: 10px;
    }
    .ds-btn-primary:hover {
      background: #f4f4f5;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35), 0 0 28px rgba(255, 255, 255, 0.3);
      transform: translateY(-1px);
    }
    .ds-btn-primary:active {
      transform: translateY(0);
    }
    .ds-btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .spinner {
      display: none;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(0, 0, 0, 0.25);
      border-top-color: #0a0a0a;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .terminal-footer {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      margin-top: 24px;
      padding-top: 18px;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      font-size: 12px;
      color: rgba(255, 255, 255, 0.4);
    }
    .footer-link {
      display: flex;
      align-items: center;
      gap: 5px;
      color: rgba(255, 255, 255, 0.45);
      text-decoration: none;
      transition: color 0.2s;
    }
    .footer-link:hover {
      color: rgba(255, 255, 255, 0.9);
    }
    .footer-divider {
      color: rgba(255, 255, 255, 0.2);
    }
    .footer-copy {
      color: rgba(255, 255, 255, 0.35);
      font-family: ui-monospace, monospace;
      font-size: 11px;
    }
  </style>
</head>
<body>
  <canvas id="heroCanvas"></canvas>

  <header class="ds-header">
    <div class="ds-header-inner">
      <div class="ds-logo-group">
        <svg width="143" height="23" viewBox="0 0 143 23" fill="none">
          <path d="M78.6784 18.6813H77.1077V16.2462H78.6784C79.6513 16.2462 80.6341 16.0037 81.2672 15.3298C81.9009 14.6559 82.14 13.6222 82.14 12.589C82.14 11.5559 81.9109 10.5222 81.2672 9.84884C80.6246 9.17496 79.6513 8.93245 78.6784 8.93245C77.7056 8.93245 76.7227 9.17496 76.0885 9.84884C75.4549 10.5227 75.2157 11.5559 75.2157 12.589V22.5899H72.4604V6.50684H75.2157V7.53106H75.7209C75.7756 7.46792 75.8304 7.41428 75.8857 7.36064C76.5752 6.73146 77.6307 6.50684 78.6684 6.50684C80.2944 6.50684 81.9193 6.91138 82.9849 8.03451C84.0499 9.15764 84.4265 10.8826 84.4265 12.5991C84.4265 14.3156 84.0404 16.0316 82.9849 17.1637C81.9288 18.2958 80.2944 18.6824 78.6784 18.6824V18.6813Z" fill="currentColor"/>
          <path d="M36.7486 6.93999H38.3188V9.37511H36.7486C35.7752 9.37511 34.7929 9.61762 34.1593 10.2915C33.5256 10.9654 33.287 11.9991 33.287 13.0323C33.287 14.0654 33.5167 15.0986 34.1593 15.7725C34.8019 16.4463 35.7752 16.6888 36.7486 16.6888C37.722 16.6888 38.7049 16.4463 39.3385 15.7725C39.9722 15.0986 40.2108 14.0654 40.2108 13.0323V3.02246H42.9655V19.115H40.2108V18.0908H39.7056C39.6503 18.1534 39.5955 18.2076 39.5402 18.2612C38.8513 18.8898 37.7952 19.115 36.7576 19.115C35.1321 19.115 33.5066 18.711 32.4416 17.5879C31.3766 16.4648 31 14.7393 31 13.0233C31 11.3073 31.3856 9.5908 32.4416 8.45873C33.5066 7.3356 35.1321 6.93999 36.7486 6.93999Z" fill="currentColor"/>
          <path d="M56.7855 12.8145V13.794H49.4483V11.8445H54.3151C54.2051 11.1348 53.948 10.4699 53.4887 9.98433C52.8277 9.28363 51.8079 9.03218 50.7982 9.03218C49.7886 9.03218 48.7688 9.28363 48.1078 9.98433C47.4468 10.685 47.2076 11.7545 47.2076 12.8151C47.2076 13.8756 47.4462 14.9535 48.1078 15.6452C48.7688 16.337 49.788 16.5979 50.7982 16.5979C51.8085 16.5979 52.8277 16.3465 53.4887 15.6452C53.5804 15.5463 53.6631 15.4385 53.7458 15.3306H56.4642C56.2256 16.1755 55.849 16.9393 55.2796 17.5322C54.1777 18.6911 52.479 19.1135 50.7982 19.1135C49.1175 19.1135 47.4188 18.7 46.3169 17.5322C45.215 16.3644 44.811 14.5852 44.811 12.8151C44.811 11.0449 45.2061 9.25681 46.3169 8.09792C47.4283 6.93903 49.1175 6.5166 50.7982 6.5166C52.479 6.5166 54.1777 6.93009 55.2796 8.09792C56.3904 9.26575 56.7855 11.0449 56.7855 12.8151V12.8145Z" fill="currentColor"/>
          <path d="M70.6151 12.8145V13.794H63.2779V11.8445H68.1447C68.0341 11.1348 67.7776 10.4699 67.3183 9.98433C66.6573 9.28363 65.6375 9.03218 64.6278 9.03218C63.6181 9.03218 62.5984 9.28363 61.9374 9.98433C61.2763 10.685 61.0372 11.7545 61.0372 12.8151C61.0372 13.8756 61.2758 14.9535 61.9374 15.6452C62.5984 16.337 63.6181 16.5979 64.6278 16.5979C65.6375 16.5979 66.6573 16.3465 67.3183 15.6452C67.4105 15.5463 67.4927 15.4385 67.5748 15.3306H70.2938C70.0546 16.1755 69.678 16.9393 69.1086 17.5322C68.0067 18.6911 66.3081 19.1135 64.6278 19.1135C62.9476 19.1135 61.2484 18.7 60.1465 17.5322C59.0446 16.3644 58.6406 14.5852 58.6406 12.8151C58.6406 11.0449 59.0357 9.25681 60.1465 8.09792C61.2579 6.93903 62.9471 6.5166 64.6278 6.5166C66.3086 6.5166 68.0067 6.93009 69.1086 8.09792C70.22 9.26575 70.6151 11.0449 70.6151 12.8151V12.8145Z" fill="currentColor"/>
          <path d="M92.2781 19.1146C93.9589 19.1146 95.657 18.8721 96.7589 18.1804C97.8607 17.4886 98.2653 16.437 98.2653 15.3949C98.2653 14.3528 97.8697 13.2922 96.7589 12.6094C95.657 11.9266 93.9583 11.6746 92.2781 11.6746C91.5612 11.6746 90.9002 11.5757 90.4319 11.3153C89.9637 11.0454 89.7893 10.6414 89.7893 10.2369C89.7893 9.83234 89.9547 9.41941 90.4319 9.15846C90.9002 8.88858 91.626 8.79917 92.3418 8.79917C93.0576 8.79917 93.7834 8.89808 94.2528 9.15846C94.721 9.42835 94.8954 9.83234 94.8954 10.2369H97.6959C97.6959 9.19422 97.3383 8.13424 96.3375 7.45142C95.3368 6.76861 93.803 6.5166 92.2786 6.5166C90.7543 6.5166 89.2211 6.75911 88.2197 7.45142C87.219 8.14318 86.8603 9.19422 86.8603 10.2369C86.8603 11.2796 87.2184 12.3395 88.2197 13.0224C89.2205 13.7052 90.7538 13.9572 92.2786 13.9572C93.0682 13.9572 93.941 14.0561 94.464 14.3165C94.9881 14.5774 95.1714 14.9903 95.1714 15.3949C95.1714 15.7994 94.9881 16.2124 94.464 16.4733C93.941 16.7337 93.1419 16.8326 92.3524 16.8326C91.5629 16.8326 90.7543 16.7337 90.2397 16.4733C89.7256 16.2129 89.5323 15.7994 89.5323 15.3949H86.2998C86.2998 16.4376 86.6943 17.4975 87.8063 18.1804C88.9171 18.8632 90.5979 19.1146 92.2786 19.1146H92.2781Z" fill="currentColor"/>
          <path d="M112.094 12.8145V13.794H104.757V11.8445H109.624C109.514 11.1348 109.257 10.4699 108.798 9.98433C108.136 9.28363 107.117 9.03218 106.106 9.03218C105.095 9.03218 104.077 9.28363 103.416 9.98433C102.755 10.685 102.517 11.7545 102.517 12.8151C102.517 13.8756 102.755 14.9535 103.416 15.6452C104.077 16.337 105.097 16.5979 106.106 16.5979C107.116 16.5979 108.136 16.3465 108.798 15.6452C108.889 15.5463 108.972 15.4385 109.054 15.3306H111.772C111.533 16.1755 111.157 16.9393 110.588 17.5322C109.486 18.6911 107.787 19.1135 106.106 19.1135C104.425 19.1135 102.727 18.7 101.625 17.5322C100.524 16.3644 100.12 14.5852 100.12 12.8151C100.12 11.0449 100.515 9.25681 101.625 8.09792C102.737 6.93903 104.427 6.5166 106.106 6.5166C107.786 6.5166 109.486 6.93009 110.588 8.09792C111.699 9.26575 112.093 11.0449 112.093 12.8151L112.094 12.8145Z" fill="currentColor"/>
          <path d="M125.924 12.8145V13.794H118.586V11.8445H123.453C123.344 11.1348 123.086 10.4699 122.627 9.98433C121.966 9.28363 120.947 9.03218 119.936 9.03218C118.926 9.03218 117.907 9.28363 117.246 9.98433C116.585 10.685 116.346 11.7545 116.346 12.8151C116.346 13.8756 116.585 14.9535 117.246 15.6452C117.907 16.337 118.927 16.5979 119.936 16.5979C120.946 16.5979 121.966 16.3465 122.627 15.6452C122.719 15.5463 122.801 15.4385 122.884 15.3306H125.602C125.363 16.1755 124.987 16.9393 124.418 17.5322C123.316 18.6911 121.617 19.1135 119.936 19.1135C118.256 19.1135 116.558 18.7 115.456 17.5322C114.354 16.3644 113.949 14.5852 113.949 12.8151C113.949 11.0449 114.344 9.25681 115.456 8.09792C116.566 6.93903 118.256 6.5166 119.936 6.5166C121.617 6.5166 123.315 6.93009 124.418 8.09792C125.529 9.26575 125.924 11.0449 125.924 12.8151V12.8145Z" fill="currentColor"/>
          <path d="M130.524 3.02246H127.77V19.115H130.524V3.02246Z" fill="currentColor"/>
          <path d="M135.227 12.4374L139.744 19.1136H136.337L131.819 12.4374L136.337 7.07324H139.744L135.227 12.4374Z" fill="currentColor"/>
          <g clip-path="url(#clip0_logo)">
            <path d="M26.5174 3.39471C26.235 3.2567 26.1137 3.52006 25.9487 3.65346C25.8923 3.69659 25.8446 3.75294 25.7969 3.80469C25.3846 4.24516 24.9027 4.53439 24.2737 4.49989C23.3536 4.44814 22.5682 4.73737 21.8735 5.44119C21.7258 4.57349 21.2353 4.0554 20.4889 3.72304C20.0985 3.55054 19.7034 3.37746 19.4297 3.00197C19.2388 2.73459 19.1865 2.43673 19.091 2.14289C19.0301 1.96579 18.9697 1.78466 18.7656 1.75418C18.5442 1.71968 18.4574 1.90541 18.3705 2.06067C18.0232 2.69549 17.8887 3.39471 17.9019 4.10313C17.9324 5.6965 18.6051 6.96556 19.9421 7.86834C20.0939 7.97184 20.133 8.07535 20.0852 8.22658C19.9938 8.53766 19.8857 8.83955 19.7903 9.15063C19.7293 9.34901 19.6384 9.39271 19.4257 9.30588C18.692 8.9994 18.0583 8.54571 17.4982 7.99772C16.5477 7.07827 15.6881 6.06336 14.6162 5.26869C14.3644 5.08296 14.1125 4.91045 13.8521 4.746C12.7584 3.68394 13.9952 2.81164 14.2816 2.70814C14.5812 2.60003 14.3857 2.22857 13.4179 2.23317C12.4502 2.2372 11.5646 2.56151 10.4359 2.99335C10.2708 3.05832 10.0972 3.10547 9.91951 3.14457C8.8954 2.95022 7.83162 2.90709 6.72069 3.03245C4.62877 3.26533 2.95777 4.25436 1.72954 5.94261C0.254043 7.97184 -0.0932678 10.2777 0.33167 12.6824C0.778458 15.2171 2.07225 17.3153 4.06008 18.9558C6.12152 20.6567 8.49577 21.4905 11.2047 21.3306C12.8498 21.2358 14.6812 21.0155 16.7473 19.2669C17.2682 19.5262 17.8151 19.6297 18.7219 19.7074C19.4205 19.7723 20.0933 19.6729 20.6143 19.5648C21.4302 19.3923 21.3739 18.6367 21.0789 18.4981C18.6874 17.3843 19.2124 17.8374 18.7351 17.4706C19.9501 16.033 21.8063 13.4776 22.379 9.99821C22.4353 9.61409 22.5072 9.073 22.4986 8.76192C22.494 8.57216 22.5377 8.49856 22.7545 8.47671C23.3536 8.40771 23.935 8.24383 24.4692 7.94999C26.0188 7.10357 26.6439 5.71318 26.7911 4.04678C26.8129 3.79204 26.7865 3.52869 26.5174 3.39471ZM13.0143 18.3946C10.6964 16.5724 9.5722 15.9726 9.10816 15.9985C8.67402 16.0244 8.75222 16.5212 8.84768 16.8449C8.94773 17.1646 9.07768 17.3849 9.25996 17.6655C9.38589 17.8512 9.47272 18.1272 9.13404 18.3348C8.38766 18.7965 7.08985 18.1796 7.0289 18.1491C5.51833 17.2595 4.25559 16.0853 3.36546 14.4793C2.50581 12.9337 2.0067 11.2753 1.92447 9.50542C1.90262 9.07818 2.02855 8.92695 2.45406 8.84932C3.01413 8.74582 3.59144 8.72397 4.15093 8.80619C6.51656 9.15178 8.53027 10.2092 10.2185 11.8848C11.1822 12.8388 11.9114 13.979 12.6623 15.0929C13.461 16.2757 14.3201 17.4027 15.4144 18.3268C15.8008 18.6505 16.109 18.8966 16.404 19.0783C15.5144 19.1778 14.0297 19.1991 13.0143 18.3958V18.3946ZM14.1252 11.2489C14.1252 11.0591 14.277 10.9079 14.4679 10.9079C14.511 10.9079 14.5501 10.9165 14.5852 10.9292C14.6329 10.9464 14.6766 10.9723 14.7111 11.0114C14.7721 11.0718 14.8066 11.158 14.8066 11.2489C14.8066 11.4386 14.6548 11.5899 14.4639 11.5899C14.273 11.5899 14.1252 11.4386 14.1252 11.2489ZM17.5759 13.0188C17.3545 13.1096 17.1331 13.1873 16.9203 13.1959C16.5903 13.2131 16.2303 13.0791 16.0348 12.9153C15.7312 12.6605 15.5139 12.5179 15.423 12.0734C15.3839 11.8837 15.4057 11.5899 15.4402 11.4214C15.5185 11.0585 15.4316 10.8257 15.1757 10.614C14.9676 10.4415 14.7025 10.3938 14.4115 10.3938C14.3029 10.3938 14.2034 10.3461 14.1292 10.3076C14.0079 10.2472 13.9078 10.096 14.0033 9.91023C14.0338 9.84985 14.1815 9.70322 14.216 9.67734C14.6111 9.45251 15.0665 9.52612 15.488 9.6946C15.8784 9.85445 16.174 10.1477 16.5989 10.5623C17.033 11.0631 17.1112 11.2011 17.3585 11.5772C17.554 11.871 17.7317 12.1729 17.8536 12.5185C17.9272 12.7341 17.8317 12.9107 17.5759 13.0188Z" fill="currentColor"/>
          </g>
          <defs>
            <clipPath id="clip0_logo">
              <rect width="26.634" height="19.6" fill="white" transform="translate(0.163086 1.75)"/>
            </clipPath>
          </defs>
        </svg>
        <span class="ds-badge-wrap">
          <span class="ds-badge-inner">Harness</span>
        </span>
      </div>
      <div class="ds-locale-toggle">
        <button type="button" class="ds-locale-btn active" id="btnZh" onclick="setLang('zh')">中文</button>
        <button type="button" class="ds-locale-btn" id="btnEn" onclick="setLang('en')">EN</button>
      </div>
    </div>
  </header>

  <main class="main-content">
    <div class="super-badge-wrap">
      <span class="super-badge-inner" id="superBadge">${copy.badge}</span>
    </div>
    <h1 class="hero-title" id="heroTitle">${copy.heroTitle}</h1>
    <p class="hero-desc" id="heroDesc">${copy.heroDesc}</p>

    <div class="terminal-card">
      <div class="terminal-bar">
        <div class="traffic-lights">
          <span class="traffic-dot dot-red"></span>
          <span class="traffic-dot dot-yellow"></span>
          <span class="traffic-dot dot-green"></span>
        </div>
        <div class="terminal-title" id="terminalTitle">${copy.terminalTitle}</div>
        <div class="terminal-badge">
          <span class="badge-status-dot"></span>
          <span id="gatewayStatusText">${copy.gatewayStatus}</span>
        </div>
      </div>

      <div class="terminal-body">
        <div id="errorBox" class="error-box">
          <svg class="error-icon" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
          </svg>
          <span id="errorMsg">${copy.errorMsg}</span>
        </div>

        <form id="loginForm" onsubmit="return handleLogin(event)">
          <div class="form-group">
            <label class="form-label" for="username" id="labelUsername">${copy.usernameLabel}</label>
            <div class="input-wrapper">
              <input type="text" id="username" class="form-input" placeholder="${copy.usernamePlaceholder}" required autofocus autocomplete="username">
              <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
              </svg>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="password" id="labelPassword">${copy.passwordLabel}</label>
            <div class="input-wrapper">
              <input type="password" id="password" class="form-input" placeholder="${copy.passwordPlaceholder}" required autocomplete="current-password">
              <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
              <button type="button" class="toggle-password" id="togglePassword" onclick="togglePasswordVisibility()" title="${copy.toggleTitle}">
                <svg id="eyeIcon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                </svg>
              </button>
            </div>
          </div>

          <button type="submit" id="submitBtn" class="ds-btn-primary">
            <span class="spinner" id="spinner"></span>
            <span id="btnText">${copy.submit}</span>
          </button>
        </form>

        <div class="terminal-footer">
          <a href="https://github.com/deepseek-ai/deepseek-harness" target="_blank" rel="noopener noreferrer" class="footer-link">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
            </svg>
            <span>GitHub</span>
          </a>
          <span class="footer-divider">·</span>
          <a href="https://deepseek-harness.github.io/deepseek-harness/guide/quickstart" target="_blank" rel="noopener noreferrer" class="footer-link">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
              <path d="M11.24 4.75V6.15H4.76V4.75H11.24Z" fill="currentColor"/>
              <path d="M9.4 7.8V9.2H4.76V7.8H9.4Z" fill="currentColor"/>
              <rect x="2" y="1" width="12" height="14" rx="2" stroke="currentColor" stroke-width="1.2"/>
            </svg>
            <span id="docLinkText">${copy.docs}</span>
          </a>
          <span class="footer-divider">·</span>
          <span class="footer-copy">Cordis Kernel</span>
        </div>
      </div>
    </div>
  </main>

  <script>
    const I18N = ${i18nJson};
    let currentLang = "${copy.lang.startsWith("zh") ? "zh" : "en"}";

    function updateTexts() {
      const c = I18N[currentLang] || I18N.zh;
      document.documentElement.lang = c.lang;
      document.title = "DeepSeek Harness - " + c.heroTitle;
      const superBadge = document.getElementById("superBadge");
      if (superBadge) superBadge.textContent = c.badge;
      const heroTitle = document.getElementById("heroTitle");
      if (heroTitle) heroTitle.textContent = c.heroTitle;
      const heroDesc = document.getElementById("heroDesc");
      if (heroDesc) heroDesc.textContent = c.heroDesc;
      const gatewayStatusText = document.getElementById("gatewayStatusText");
      if (gatewayStatusText) gatewayStatusText.textContent = c.gatewayStatus;
      const terminalTitle = document.getElementById("terminalTitle");
      if (terminalTitle) terminalTitle.textContent = c.terminalTitle;
      const labelUsername = document.getElementById("labelUsername");
      if (labelUsername) labelUsername.textContent = c.usernameLabel;
      const usernameInput = document.getElementById("username");
      if (usernameInput) usernameInput.placeholder = c.usernamePlaceholder;
      const labelPassword = document.getElementById("labelPassword");
      if (labelPassword) labelPassword.textContent = c.passwordLabel;
      const passwordInput = document.getElementById("password");
      if (passwordInput) passwordInput.placeholder = c.passwordPlaceholder;
      const togglePassword = document.getElementById("togglePassword");
      if (togglePassword) togglePassword.title = c.toggleTitle;
      const btnText = document.getElementById("btnText");
      if (btnText && !btnText.getAttribute("data-busy")) btnText.textContent = c.submit;
      const docLinkText = document.getElementById("docLinkText");
      if (docLinkText) docLinkText.textContent = c.docs;

      const btnZh = document.getElementById("btnZh");
      const btnEn = document.getElementById("btnEn");
      if (currentLang === "zh") {
        if (btnZh) btnZh.classList.add("active");
        if (btnEn) btnEn.classList.remove("active");
      } else {
        if (btnEn) btnEn.classList.add("active");
        if (btnZh) btnZh.classList.remove("active");
      }
    }

    function setLang(lang) {
      if (I18N[lang]) {
        currentLang = lang;
        try { localStorage.setItem("dsh_login_lang", lang); } catch (e) {}
        updateTexts();
      }
    }

    try {
      const saved = localStorage.getItem("dsh_login_lang");
      if (saved && I18N[saved]) {
        currentLang = saved;
        updateTexts();
      }
    } catch (e) {}

    // DSH Official Canvas Physics Grid
    (function initPhysicsGrid() {
      const canvas = document.getElementById("heroCanvas");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      let dots = [], cols = 0, rows = 0, width = 0, height = 0;
      const spacing = 90;
      const mouse = { x: NaN, y: NaN };
      let animId = 0;

      function setupGrid() {
        cols = Math.ceil(width / spacing) + 1;
        rows = Math.ceil(height / spacing) + 1;
        const startX = (width - (cols - 1) * spacing) / 2;
        const startY = (height - (rows - 1) * spacing) / 2;
        dots = [];
        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols; c++) {
            const x = startX + spacing * c;
            const y = startY + spacing * r;
            dots.push({ restX: x, restY: y, x, y, vx: 0, vy: 0 });
          }
        }
      }

      function onResize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        setupGrid();
      }

      window.addEventListener("resize", onResize);
      window.addEventListener("mousemove", (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
      });
      window.addEventListener("mouseleave", () => {
        mouse.x = NaN;
        mouse.y = NaN;
      });

      let lastTime = 0;
      const interval = 1000 / 30;

      function render(time) {
        if (time - lastTime < interval) {
          animId = requestAnimationFrame(render);
          return;
        }
        lastTime = time - (time - lastTime) % interval;

        ctx.clearRect(0, 0, width, height);

        const mx = mouse.x;
        const my = mouse.y;

        for (let i = 0; i < dots.length; i++) {
          const d = dots[i];
          if (!isNaN(mx) && !isNaN(my)) {
            const dx = d.x - mx;
            const dy = d.y - my;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 140 && dist > 0.1) {
              const force = (1 - dist / 140) * 30;
              d.vx += (dx / dist) * force * 0.1;
              d.vy += (dy / dist) * force * 0.1;
            }
          }
          const springX = d.restX - d.x;
          const springY = d.restY - d.y;
          d.vx += 0.05 * springX;
          d.vy += 0.05 * springY;
          d.vx *= 0.85;
          d.vy *= 0.85;
          d.x += d.vx;
          d.y += d.vy;
        }

        ctx.strokeStyle = "rgba(60, 100, 160, 0.12)";
        ctx.lineWidth = 0.6;

        for (let r = 0; r < rows; r++) {
          for (let c = 0; c < cols - 1; c++) {
            const p1 = dots[r * cols + c];
            const p2 = dots[r * cols + c + 1];
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 20) continue;
            const nx = dx / dist;
            const ny = dy / dist;
            ctx.beginPath();
            ctx.moveTo(p1.x + 8 * nx, p1.y + 8 * ny);
            ctx.lineTo(p2.x - 8 * nx, p2.y - 8 * ny);
            ctx.stroke();
          }
        }

        for (let c = 0; c < cols; c++) {
          for (let r = 0; r < rows - 1; r++) {
            const p1 = dots[r * cols + c];
            const p2 = dots[(r + 1) * cols + c];
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 20) continue;
            const nx = dx / dist;
            const ny = dy / dist;
            ctx.beginPath();
            ctx.moveTo(p1.x + 8 * nx, p1.y + 8 * ny);
            ctx.lineTo(p2.x - 8 * nx, p2.y - 8 * ny);
            ctx.stroke();
          }
        }

        ctx.fillStyle = "rgba(100, 150, 240, 1)";
        for (let i = 0; i < dots.length; i++) {
          const d = dots[i];
          let radius = 1.8;
          let alpha = 0.22;
          if (!isNaN(mx) && !isNaN(my)) {
            const dx = d.x - mx;
            const dy = d.y - my;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 140) {
              const factor = 1 - dist / 140;
              radius = 1.8 + 2.0 * factor;
              alpha = 0.22 + 0.45 * factor;
            }
          }
          ctx.globalAlpha = alpha;
          ctx.fillRect(d.x - radius, d.y - radius, radius * 2, radius * 2);
        }
        ctx.globalAlpha = 1.0;

        animId = requestAnimationFrame(render);
      }

      onResize();
      animId = requestAnimationFrame(render);
    })();

    function togglePasswordVisibility() {
      const pwdInput = document.getElementById("password");
      const eyeIcon = document.getElementById("eyeIcon");
      if (pwdInput.type === "password") {
        pwdInput.type = "text";
        eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/>';
      } else {
        pwdInput.type = "password";
        eyeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>';
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
      const c = I18N[currentLang] || I18N.zh;

      errorBox.style.display = "none";
      submitBtn.disabled = true;
      spinner.style.display = "inline-block";
      btnText.setAttribute("data-busy", "true");
      btnText.textContent = c.verifying;

      try {
        const res = await fetch("/api/auth.login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.ok) {
          btnText.textContent = c.success;
          setTimeout(() => {
            window.location.reload();
          }, 300);
        } else {
          submitBtn.disabled = false;
          spinner.style.display = "none";
          btnText.removeAttribute("data-busy");
          btnText.textContent = c.submit;
          errorMsg.textContent = data.error || c.errorMsg;
          errorBox.style.display = "flex";
          document.getElementById("password").focus();
        }
      } catch (err) {
        submitBtn.disabled = false;
        spinner.style.display = "none";
        btnText.removeAttribute("data-busy");
        btnText.textContent = c.submit;
        errorMsg.textContent = c.networkError;
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

