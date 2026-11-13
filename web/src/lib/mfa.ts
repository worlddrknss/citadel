// Console multi-factor authentication (TOTP) client and helpers.
//
// Contracts:
//   POST /v1/login                      → Me | { mfaRequired: true, mfaToken }
//   POST /v1/login/mfa                  { mfaToken, code | recoveryCode } → Me
//   GET  /v1/account/mfa                → MfaStatus
//   POST /v1/account/mfa/enroll/start   → MfaEnrollment (secret shown once)
//   POST /v1/account/mfa/enroll/confirm { code } → { enabled, recoveryCodes, me? }
//   POST /v1/account/mfa/disable        { password, code | recoveryCode }
//   POST /v1/account/mfa/recovery-codes { password, code | recoveryCode } → { recoveryCodes }
//   POST /v1/admin/users/mfa/reset      { username, confirm }

import { req, type Me } from './api.ts';
import { encode } from 'uqr';

export interface MfaStatus {
  enabled: boolean;
  pending: boolean;
  enabledAt?: string;
  recoveryCodesLeft: number;
  /** The organization requires MFA for password sign-in. */
  required: boolean;
  algorithm: string;
  digits: number;
  period: number;
}

export interface MfaEnrollment {
  secret: string;
  otpauthUri: string;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
}

export interface MfaFactor {
  code?: string;
  recoveryCode?: string;
}

export type LoginResult = (Me & { authOff?: boolean; mfaRequired?: false }) | { mfaRequired: true; mfaToken: string };

export const mfaApi = {
  status: () => req<MfaStatus>('/v1/account/mfa'),
  start: () => req<MfaEnrollment>('/v1/account/mfa/enroll/start', { method: 'POST' }),
  confirm: (code: string) =>
    req<{ enabled: boolean; recoveryCodes: string[]; me?: Me }>('/v1/account/mfa/enroll/confirm', {
      method: 'POST',
      body: JSON.stringify({ code })
    }),
  disable: (password: string, factor: MfaFactor) =>
    req<{ disabled: boolean }>('/v1/account/mfa/disable', { method: 'POST', body: JSON.stringify({ password, ...factor }) }),
  regenerate: (password: string, factor: MfaFactor) =>
    req<{ recoveryCodes: string[] }>('/v1/account/mfa/recovery-codes', {
      method: 'POST',
      body: JSON.stringify({ password, ...factor })
    }),
  loginMfa: (mfaToken: string, factor: MfaFactor) =>
    req<Me>('/v1/login/mfa', { method: 'POST', body: JSON.stringify({ mfaToken, ...factor }) }),
  adminReset: (username: string) =>
    req<{ reset: boolean; sessionsRevoked: number }>('/v1/admin/users/mfa/reset', {
      method: 'POST',
      body: JSON.stringify({ username, confirm: username })
    })
};

/** Strips spaces from a typed code; true when it is a full 6-digit code. */
export function cleanOtp(s: string): string {
  return s.replace(/\s+/g, '');
}
export function isOtp(s: string): boolean {
  return /^\d{6}$/.test(cleanOtp(s));
}

/** The secret in groups of four, easier to type into an app by hand. */
export function groupSecret(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, '$1 ');
}

/** Text file body for downloading recovery codes. */
export function recoveryCodesText(codes: string[], who: string, issuer = 'Citadel'): string {
  return [
    `${issuer} recovery codes for ${who}`,
    `Generated ${new Date().toISOString()}`,
    '',
    'Each code signs you in once if you lose your authenticator. Keep them somewhere safe.',
    '',
    ...codes,
    ''
  ].join('\n');
}

/**
 * QR code for an otpauth:// URI as an SVG path over a size×size grid
 * (including a 4-module quiet zone). Encoded locally: the secret never
 * leaves the page.
 */
export function qrPath(text: string): { size: number; d: string } {
  const qr = encode(text, { ecc: 'M', border: 4 });
  let d = '';
  qr.data.forEach((row, y) => {
    row.forEach((on, x) => {
      if (on) d += `M${x} ${y}h1v1h-1z`;
    });
  });
  return { size: qr.size, d };
}
