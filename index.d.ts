import { Context, Service } from '@deepseek-ai/cordis'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:net'

/** Plugin label used in loader logs. */
export declare const name: 'auth-webserver'

export interface AuthWebServerConfig {
  host?: '127.0.0.1' | '0.0.0.0'
  port?: number
  username?: string
  password?: string
  realm?: string
}

export interface WebRoute {
  kind: 'exact' | 'prefix'
  path: string
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
}

export interface WebUpgradeRoute {
  path: string
  handler: (req: IncomingMessage, socket: Duplex, head: Buffer) => void | Promise<void>
}

/**
 * The auth-gated web transport. Provides the `webServer` service with the
 * same registration API as the stock host webserver, plus cookie/basic
 * authentication, a bilingual login page, and the auth settings endpoints.
 *
 * Security posture (0.4.0): the credential gate runs before the stock `/api`
 * Host-header trust fence (QVD-2026-57410 hardening); binding a non-loopback
 * interface with an empty password auto-generates a random password; the
 * Host/Origin normalization only vouches for authenticated sessions; failed
 * logins are throttled per client IP; `/api/auth.get` never echoes the
 * password.
 */
export declare class AuthWebServer extends Service {
  constructor(ctx: Context, config: AuthWebServerConfig)
  get port(): number
  get host(): string
  /** Effective username: `DSH_AUTH_USER` env overrides config/state. */
  get effectiveUsername(): string
  /** Effective password: `DSH_AUTH_PASS` env overrides config/state. */
  get effectivePassword(): string
  /** Whether a password is in force (env, config, or generated). */
  get authEnabled(): boolean
  /** Whether the server binds the loopback interface only. */
  get loopbackOnly(): boolean
  register(route: WebRoute): () => void
  registerUpgrade(route: WebUpgradeRoute): () => void
  registerFallback(handler: WebRoute['handler']): () => void
  tapIndex(transform: (html: string) => string): () => void
  applyIndexTaps(html: string): string
}

export default AuthWebServer
