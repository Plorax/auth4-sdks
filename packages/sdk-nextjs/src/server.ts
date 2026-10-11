// Server entry (@auth4/nextjs/server) for proxy.ts, route handlers, server components and server
// actions. Client components use the package root, @auth4/nextjs, instead.
export {
  AccessTokenError,
  Auth4Client,
  ConfigurationError,
  type AccessTokenErrorCode,
  type Auth4ClientOptions,
  type Auth4Routes,
  type CallbackErrorCode,
  type Session,
  type SocialProvider,
} from "./client.ts";
export type { AccessTokenResponse, User } from "./types.ts";
