// A tiny OpenID Connect provider for the SSO tests: discovery, JWKS, an
// authorization endpoint that signs the configured user straight in, and a
// token endpoint that returns an ES256 ID token. Plain http on 127.0.0.1,
// which the server accepts because its KMS_PUBLIC_URL is loopback http.

import { createServer, type Server } from 'node:http';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { AddressInfo } from 'node:net';

export interface FakeUser {
  sub: string;
  email: string;
  name: string;
  groups: string[];
}

export interface FakeOidc {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Who the next authorization signs in as. */
  user: FakeUser;
  close(): Promise<void>;
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');

export async function startFakeOidc(): Promise<FakeOidc> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'fake-1', use: 'sig', alg: 'ES256' };
  const codes = new Map<string, { nonce: string; user: FakeUser }>();
  const state: FakeOidc = {
    issuer: '',
    clientId: 'citadel-console',
    clientSecret: 'fake-oidc-client-secret-0123456789',
    user: { sub: 'u-1', email: 'sam@example.com', name: 'Sam SSO', groups: ['citadel-editors'] },
    close: async () => {}
  };

  const idToken = (nonce: string, u: FakeUser) => {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'fake-1' }));
    const payload = b64url(
      JSON.stringify({
        iss: state.issuer,
        aud: state.clientId,
        sub: u.sub,
        email: u.email,
        email_verified: true,
        name: u.name,
        groups: u.groups,
        nonce,
        iat: now,
        exp: now + 300
      })
    );
    const sig = sign('sha256', Buffer.from(`${header}.${payload}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return `${header}.${payload}.${b64url(sig)}`;
  };

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', state.issuer);
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, {
        issuer: state.issuer,
        authorization_endpoint: `${state.issuer}/authorize`,
        token_endpoint: `${state.issuer}/token`,
        jwks_uri: `${state.issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['ES256'],
        code_challenge_methods_supported: ['S256']
      });
    }
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
    if (url.pathname === '/authorize') {
      const code = b64url(randomBytes(16));
      codes.set(code, { nonce: url.searchParams.get('nonce') ?? '', user: { ...state.user } });
      const back = new URL(url.searchParams.get('redirect_uri') ?? '');
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state') ?? '');
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const form = new URLSearchParams(body);
        const entry = codes.get(form.get('code') ?? '');
        if (!entry) return json(400, { error: 'invalid_grant' });
        codes.delete(form.get('code')!);
        json(200, { access_token: 'fake-access', token_type: 'Bearer', expires_in: 300, id_token: idToken(entry.nonce, entry.user) });
      });
      return;
    }
    json(404, { error: 'not_found' });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  state.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  state.close = () => new Promise((resolve) => server.close(() => resolve()));
  return state;
}
