// Served to browser bundles through the package's "browser" export
// condition. Bundlers that build client code (Next.js client components,
// Vite, webpack) resolve this file instead of the SDK, so importing the SDK
// from client code fails at load instead of shipping an access key and secret
// values to every visitor.
import { SERVER_ONLY_MESSAGE } from './guard.js';

throw new Error(SERVER_ONLY_MESSAGE);
