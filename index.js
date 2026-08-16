/**
 * dsh-plugin-auth-webserver
 * 
 * DeepSeek Harness Cordis plugin providing:
 * 1. HTTP Basic Authentication & WebSocket Upgrade protection
 * 2. Automatic crypto.randomUUID polyfill for non-HTTPS / raw IP web clients
 * 3. Remote IP privileged RPC gateway trust delegation
 * 4. Interactive Web UI Settings Card integration & live auth update API
 *
 * @license MIT
 */

import { createServer } from "node:http";
import { writeFileSync } from "node:fs";
import { Service } from "@deepseek-ai/cordis";
import z from "@deepseek-ai/schemastery";

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

  constructor(ctx, config) {
    super(ctx, "webServer");
    this.config = config;

    // Register Auth Settings APIs
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

            res.writeHead(200, { "Content-Type": "application/json" });
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

  checkAuth(req) {
    const expectedUser = process.env.DSH_AUTH_USER || this.config.username || "admin";
    const expectedPass = process.env.DSH_AUTH_PASS || this.config.password || "";

    if (!expectedPass) {
      return true;
    }

    const auth = req.headers["authorization"];
    if (!auth || !auth.startsWith("Basic ")) {
      return false;
    }

    try {
      const b64 = auth.slice(6).trim();
      const decoded = Buffer.from(b64, "base64").toString("utf-8");
      const idx = decoded.indexOf(":");
      if (idx === -1) return false;
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      return user === expectedUser && pass === expectedPass;
    } catch {
      return false;
    }
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

  async [Service.init]() {
    const handle = async (req, res) => {
      if (!this.checkAuth(req)) {
        const realm = this.config.realm || "DeepSeek Harness Authentication";
        res.writeHead(401, {
          "WWW-Authenticate": `Basic realm="${realm}"`,
          "Content-Type": "text/html; charset=utf-8"
        });
        res.end("<h1>401 Unauthorized</h1><p>Access Denied: Authentication Required.</p>");
        return;
      }

      this.applySecurityHeaders(req);

      const rawPath = new URL(req.url ?? "/", "http://x").pathname;
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
