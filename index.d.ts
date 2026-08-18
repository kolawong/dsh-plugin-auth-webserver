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
 */
export declare class AuthWebServer extends Service {
  constructor(ctx: Context, config: AuthWebServerConfig)
  get port(): number
  get host(): string
  register(route: WebRoute): () => void
  registerUpgrade(route: WebUpgradeRoute): () => void
  registerFallback(handler: WebRoute['handler']): () => void
  tapIndex(transform: (html: string) => string): () => void
  applyIndexTaps(html: string): string
}

export default AuthWebServer
