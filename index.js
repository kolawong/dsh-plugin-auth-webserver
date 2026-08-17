/**
 * dsh-plugin-auth-webserver
 * 
 * DeepSeek Harness Cordis plugin providing:
 * 1. Modern DeepSeek-themed Web Login Page (Form & Cookie-based session auth)
 * 2. Fallback HTTP Basic Auth support for CLI / API clients
 * 3. WebSocket Upgrade token verification
 * 4. Automatic crypto.randomUUID polyfill for non-HTTPS / raw IP web clients
 * 5. Remote IP privileged RPC gateway trust delegation
 * 6. Interactive Web UI Settings Card integration & live auth update/logout API
 *
 * @license MIT
 */

import { createServer } from "node:http";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";

const COOKIE_NAME = "dsh_auth_token";

export class AuthWebServer extends Service {
  config;
  static Config = z.object({
    host: z.union([z.const("127.0.0.1"), z.const("0.0.0.0")]).default("0.0.0.0"),
    port: z.natural().max(65535).default(3080),
    username: z.string().default("admin"),
    password: z.string().default(""),
    realm: z.string().default("DeepSeek Harness Authentication")
  });

  exact = new Map();
  prefixes = new Map();
  upgrades = new Map();
  upgradedSockets = new Set();
  indexTaps = [];
  fallback;
  server;
  listenedPort;
  secret;

  constructor(ctx, config) {
    super(ctx, "webServer");
    this.config = config;
    this.initSecret();

    // Register Auth Settings & Login APIs
    this.register({
      kind: "exact",
      path: "/api/auth.login",
      handler: async (req, res) => {
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Method not allowed" }));
          return;
        }
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
          try {
            const data = JSON.parse(body || "{}");
            const expectedUser = process.env.DSH_AUTH_USER || this.config.username || "admin";
            const expectedPass = process.env.DSH_AUTH_PASS || this.config.password || "";

            if (!expectedPass || (data.username === expectedUser && data.password === expectedPass)) {
              const token = this.generateToken(expectedUser, expectedPass);
              const maxAge = 30 * 24 * 3600; // 30 days
              res.writeHead(200, {
                "Content-Type": "application/json",
                "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
              });
              res.end(JSON.stringify({ ok: true, username: expectedUser }));
            } else {
              res.writeHead(401, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ ok: false, error: "用户名或密码错误" }));
            }
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: err.message }));
          }
        });
      }
    });

    this.register({
      kind: "exact",
      path: "/api/auth.logout",
      handler: async (req, res) => {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
        });
        res.end(JSON.stringify({ ok: true }));
      }
    });

    this.register({
      kind: "exact",
      path: "/api/auth.get",
      handler: async (req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          ok: true,
          username: this.config.username || "admin",
          password: this.config.password || "",
          realm: this.config.realm || "DeepSeek Harness Authentication"
        }));
      }
    });

    this.register({
      kind: "exact",
      path: "/api/auth.update",
      handler: async (req, res) => {
        if (req.method !== "POST") {
          res.writeHead(405);
          res.end();
          return;
        }
        let body = "";
        req.on("data", (c) => { body += c; });
        req.on("end", () => {
          try {
            const data = JSON.parse(body);
            if (data.username !== undefined) this.config.username = String(data.username);
            if (data.password !== undefined) this.config.password = String(data.password);
            if (data.realm !== undefined) this.config.realm = String(data.realm);

            // Persist to cordis.patch.yml
            this.persistPatch();

            // Also refresh cookie for the current admin
            const token = this.generateToken(this.config.username, this.config.password);
            const maxAge = 30 * 24 * 3600;
            res.writeHead(200, {
              "Content-Type": "application/json",
              "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
            });
            res.end(JSON.stringify({
              ok: true,
              username: this.config.username,
              realm: this.config.realm
            }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: err.message }));
          }
        });
      }
    });
  }

  initSecret() {
    try {
      const secretFile = "/root/.dsh/plugins/dsh-plugin-auth-webserver/.secret";
      if (existsSync(secretFile)) {
        this.secret = readFileSync(secretFile, "utf8").trim();
      } else {
        this.secret = randomBytes(32).toString("hex");
        writeFileSync(secretFile, this.secret, "utf8");
      }
    } catch {
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
    if (isNaN(ts) || Date.now() - ts > 30 * 24 * 3600 * 1000 || ts > Date.now() + 60000) {
      return false;
    }
    const expectedSig = createHmac("sha256", this.secret).update(`${expectedUser}:${expectedPass}:${ts}`).digest("hex");
    try {
      return timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expectedSig, "hex"));
    } catch {
      return false;
    }
  }

  persistPatch() {
    try {
      const patchPath = "/root/.dsh/profiles/web/cordis.patch.yml";
      const u = (this.config.username || "admin").replace(/'/g, "''");
      const p = (this.config.password || "").replace(/'/g, "''");
      const content = `- id: webserver
  disabled: true

- insert:
    - id: webserver-auth
      name: '@custom/dsh-plugin-auth-webserver'
      inject:
        - webStartup
      config:
        host: '0.0.0.0'
        port: !!js ctx.webStartup.port ?? 3080
        username: '${u}'
        password: '${p}'
`;
      writeFileSync(patchPath, content, "utf8");
    } catch (e) {
      this.ctx.logger.warn("Failed to persist cordis.patch.yml:", e);
    }
  }

  get port() {
    return this.listenedPort;
  }

  get host() {
    return this.config.host;
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

  tapIndex(transform) {
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
    const expectedUser = process.env.DSH_AUTH_USER || this.config.username || "admin";
    const expectedPass = process.env.DSH_AUTH_PASS || this.config.password || "";

    if (!expectedPass) {
      return true;
    }

    // 1. Check Cookie
    const cookies = this.parseCookies(req);
    if (cookies[COOKIE_NAME] && this.verifyToken(cookies[COOKIE_NAME], expectedUser, expectedPass)) {
      return true;
    }

    // 2. Check HTTP Basic Authorization header (backward compatible for API/CLI)
    const auth = req.headers["authorization"];
    if (auth && auth.startsWith("Basic ")) {
      try {
        const b64 = auth.slice(6).trim();
        const decoded = Buffer.from(b64, "base64").toString("utf-8");
        const idx = decoded.indexOf(":");
        if (idx !== -1) {
          const user = decoded.slice(0, idx);
          const pass = decoded.slice(idx + 1);
          return user === expectedUser && pass === expectedPass;
        }
      } catch {}
    }

    return false;
  }

  applySecurityHeaders(req) {
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

  renderLoginPage(req, res) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>DeepSeek Harness - 访问登录</title>
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
      <p class="subtitle">远程安全访问认证 · Web Authentication</p>
    </div>

    <div id="errorBox" class="error-box">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      <span id="errorMsg">用户名或密码错误</span>
    </div>

    <form id="loginForm" onsubmit="return handleLogin(event)">
      <div class="form-group">
        <label class="form-label" for="username">用户名</label>
        <div class="input-wrapper">
          <input type="text" id="username" class="form-input" placeholder="请输入用户名" required autofocus autocomplete="username">
          <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
          </svg>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label" for="password">访问密码</label>
        <div class="input-wrapper">
          <input type="password" id="password" class="form-input" placeholder="请输入访问密码" required autocomplete="current-password">
          <svg class="input-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
          </svg>
          <button type="button" class="toggle-password" id="togglePassword" onclick="togglePasswordVisibility()" title="显示/隐藏密码">
            <svg id="eyeIcon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
            </svg>
          </button>
        </div>
      </div>

      <button type="submit" id="submitBtn" class="submit-btn">
        <span class="spinner" id="spinner"></span>
        <span id="btnText">登 录</span>
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
      btnText.textContent = "正在验证...";

      try {
        const res = await fetch("/api/auth.login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (data.ok) {
          btnText.textContent = "登录成功，正在进入...";
          setTimeout(() => {
            window.location.reload();
          }, 300);
        } else {
          submitBtn.disabled = false;
          spinner.style.display = "none";
          btnText.textContent = "登 录";
          errorMsg.textContent = data.error || "用户名或密码错误";
          errorBox.style.display = "flex";
          document.getElementById("password").focus();
        }
      } catch (err) {
        submitBtn.disabled = false;
        spinner.style.display = "none";
        btnText.textContent = "登 录";
        errorMsg.textContent = "网络请求失败，请稍后重试";
        errorBox.style.display = "flex";
      }
      return false;
    }
  </script>
</body>
</html>`;

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end(html);
  }

  async [Service.init]() {
    const handle = async (req, res) => {
      const rawPath = new URL(req.url ?? "/", "http://x").pathname;

      // Allow public auth endpoints unconditionally
      if (rawPath === "/api/auth.login") {
        const route = this.exact.get("/api/auth.login");
        if (route) {
          await route.handler(req, res);
          return;
        }
      }

      if (!this.checkAuth(req)) {
        // If it is an HTML navigation request (browser viewing the page), render the custom Login Page!
        const accept = req.headers.accept || "";
        const isHtmlRequest = rawPath === "/" || rawPath === "/index.html" || accept.includes("text/html");

        if (isHtmlRequest && req.method === "GET") {
          this.renderLoginPage(req, res);
          return;
        }

        // For non-HTML / API requests, return 401 JSON without WWW-Authenticate header
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "Authentication required" }));
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
        this.ctx.logger.warn(err instanceof Error ? err : new Error(String(err)));
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

  applyIndexTaps(html) {
    let out = html;
    for (const transform of this.indexTaps) out = transform(out);

    // Polyfill crypto.randomUUID for non-HTTPS / IP environments
    const polyfill = `<script>
(function() {
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

export default AuthWebServer;
