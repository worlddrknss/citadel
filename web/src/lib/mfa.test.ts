import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanOtp, groupSecret, isOtp, mfaApi, qrPath, recoveryCodesText } from './mfa.ts';
import MfaEnroll from './components/MfaEnroll.svelte';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe('mfa helpers', () => {
  it('accepts only 6-digit codes, ignoring spaces', () => {
    expect(isOtp('123456')).toBe(true);
    expect(isOtp('123 456')).toBe(true);
    expect(cleanOtp(' 123 456 ')).toBe('123456');
    for (const bad of ['', '12345', '1234567', 'abcdef', '12a456']) expect(isOtp(bad)).toBe(false);
  });

  it('groups the secret for manual entry', () => {
    expect(groupSecret('ABCDEFGHIJ')).toBe('ABCD EFGH IJ');
  });

  it('writes a recovery code file', () => {
    const t = recoveryCodesText(['aaaa-bbbb-cccc', 'dddd-eeee-ffff'], 'alice');
    expect(t).toContain('recovery codes for alice');
    expect(t).toContain('aaaa-bbbb-cccc\ndddd-eeee-ffff');
  });

  it('encodes a QR code locally as a square module grid with a quiet zone', () => {
    const uri = 'otpauth://totp/Citadel:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Citadel&algorithm=SHA256&digits=6&period=30';
    const { size, d } = qrPath(uri);
    // Version 5+ for this length: 37+ modules plus 2×4 border.
    expect(size).toBeGreaterThanOrEqual(45);
    expect(d).toMatch(/^M\d+ \d+h1v1h-1z/);
    // Nothing is drawn in the quiet zone.
    const cells = [...d.matchAll(/M(\d+) (\d+)/g)].map((m) => [Number(m[1]), Number(m[2])]);
    expect(cells.every(([x, y]) => x >= 4 && y >= 4 && x < size - 4 && y < size - 4)).toBe(true);
    // Deterministic.
    expect(qrPath(uri).d).toBe(d);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sends the factor to /v1/login/mfa', async () => {
    fetchMock.mockResolvedValue(json(200, { username: 'alice' }));
    await mfaApi.loginMfa('tok', { recoveryCode: 'aaaa-bbbb-cccc' });
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe('/v1/login/mfa');
    expect(JSON.parse(init.body)).toEqual({ mfaToken: 'tok', recoveryCode: 'aaaa-bbbb-cccc' });
  });

  it('admin reset repeats the username as confirmation', async () => {
    fetchMock.mockResolvedValue(json(200, { reset: true, sessionsRevoked: 1 }));
    await mfaApi.adminReset('bob');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ username: 'bob', confirm: 'bob' });
  });
});

describe('MfaEnroll', () => {
  it('shows the QR code, confirms a code and then the recovery codes', async () => {
    const user = userEvent.setup();
    const codes = Array.from({ length: 10 }, (_, i) => `aaaa-bbbb-cc${String(i).padStart(2, '0')}`);
    fetchMock
      .mockResolvedValueOnce(
        json(200, {
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          otpauthUri: 'otpauth://totp/Citadel:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256',
          issuer: 'Citadel',
          account: 'alice',
          algorithm: 'SHA256',
          digits: 6,
          period: 30
        })
      )
      .mockResolvedValueOnce(json(400, { error: 'invalid_code', message: 'that code is not valid' }))
      .mockResolvedValueOnce(json(200, { enabled: true, recoveryCodes: codes }));
    const ondone = vi.fn();
    render(MfaEnroll, { username: 'alice', ondone });

    expect(await screen.findByRole('img', { name: /QR code/ })).toBeInTheDocument();
    expect(screen.getByText(/must support SHA-256/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Enter the key by hand/ }));
    expect(screen.getByText('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ')).toBeInTheDocument();

    const input = screen.getByLabelText(/6-digit code/);
    expect(input).toHaveAttribute('autocomplete', 'one-time-code');
    await user.type(input, '12');
    await user.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(screen.getByRole('alert')).toHaveTextContent('6-digit');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await user.clear(input);
    await user.type(input, '000000');
    await user.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(await screen.findByText('that code is not valid')).toBeInTheDocument();

    await user.type(screen.getByLabelText(/6-digit code/), '123456');
    await user.click(screen.getByRole('button', { name: 'Turn on' }));
    expect(await screen.findByText(codes[0])).toBeInTheDocument();
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ code: '123456' });

    const finish = screen.getByRole('button', { name: 'Finish' });
    expect(finish).toBeDisabled();
    await user.click(screen.getByLabelText("I've saved my recovery codes"));
    await user.click(finish);
    expect(ondone).toHaveBeenCalledOnce();
  });
});
