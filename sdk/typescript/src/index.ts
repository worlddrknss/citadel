/**
 * TypeScript client for Citadel's native /v1 API.
 *
 * Server-only. See the README for Next.js usage and the `server-only` pattern.
 * @packageDocumentation
 */
import { assertServerRuntime } from './guard.js';

// Fail loudly the moment the SDK is evaluated in a browser, in case a bundler
// ignored the package's "browser" export condition.
assertServerRuntime();

export { Citadel, type CitadelOptions } from './client.js';
export { AgentHttpResult, CitadelAgent, type CitadelAgentOptions, type WaitForAccessOptions } from './agent.js';
export { VERSION } from './version.js';
export { CitadelConnectionError, CitadelError, CitadelTimeoutError } from './errors.js';
export type { CallSpec, NextFetchOptions, RequestOptions } from './http.js';
export { clearSecretsCache, loadSecrets, type LoadSecretsOptions } from './next.js';
export { isBrowserRuntime, SERVER_ONLY_MESSAGE } from './guard.js';
export type * from './types.js';
