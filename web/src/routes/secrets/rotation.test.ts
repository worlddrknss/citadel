import { describe, expect, it } from 'vitest';
import { defaultForm, formFromStatus, requestFromForm, scheduleLabel, statusBadge, validateForm, type RotationStatus } from './rotation';

const coord = { project: 'pay', env: 'dev', path: '/', key: 'DB' };

function status(over: Partial<RotationStatus>): RotationStatus {
  return { enabled: true, mode: 'builtin', schedule: {}, status: '', due: false, history: [], ...over };
}

describe('rotation form', () => {
  it('builds a random rotator request with only non-default options', () => {
    const f = { ...defaultForm(), length: 40, excludePunctuation: true, jsonKey: ' password ' };
    expect(requestFromForm(coord, f, true)).toEqual({
      ...coord,
      rotator: { type: 'random', config: { length: 40, excludePunctuation: true, jsonKey: 'password' } },
      afterDays: 30,
      rotateImmediately: true
    });
  });

  it('maps schedule kinds and the window to AWS rules', () => {
    expect(requestFromForm(coord, { ...defaultForm(), scheduleKind: 'hours', hours: 6, windowHours: 2 }, false)).toMatchObject({
      scheduleExpression: 'rate(6 hours)',
      duration: '2h'
    });
    const cron = requestFromForm(coord, { ...defaultForm(), scheduleKind: 'cron', cron: ' cron(0 4 ? * MON *) ' }, false);
    expect(cron.scheduleExpression).toBe('cron(0 4 ? * MON *)');
    expect(cron.afterDays).toBeUndefined();
  });

  it('sends webhook and postgresql options', () => {
    expect(requestFromForm(coord, { ...defaultForm(), type: 'webhook', url: ' https://hook.example.com/r ' }, false).rotator).toEqual({
      type: 'webhook',
      config: { url: 'https://hook.example.com/r' }
    });
    expect(
      requestFromForm(coord, { ...defaultForm(), type: 'postgresql', strategy: 'alternating-users', adminSecretArn: 'arn:x' }, false).rotator
    ).toEqual({ type: 'postgresql', config: { strategy: 'alternating-users', adminSecretArn: 'arn:x' } });
  });

  it('round-trips the server status into the form', () => {
    const f = formFromStatus(
      status({
        rotator: { type: 'webhook', config: { url: 'https://h.example.com' } },
        schedule: { expression: 'rate(8 hours)', duration: '3h' }
      })
    );
    expect(f).toMatchObject({ type: 'webhook', url: 'https://h.example.com', scheduleKind: 'hours', hours: 8, windowHours: 3 });
    expect(formFromStatus(status({ schedule: { afterDays: 7 } }))).toMatchObject({ scheduleKind: 'days', days: 7 });
    expect(formFromStatus(status({ schedule: { expression: 'cron(0 1 * * ? *)' } }))).toMatchObject({ scheduleKind: 'cron', cron: 'cron(0 1 * * ? *)' });
  });

  it('validates like the server', () => {
    expect(validateForm(defaultForm())).toBe('');
    expect(validateForm({ ...defaultForm(), days: 0 })).toMatch(/1 to 1000/);
    expect(validateForm({ ...defaultForm(), scheduleKind: 'hours', hours: 3 })).toMatch(/4 to 23/);
    expect(validateForm({ ...defaultForm(), scheduleKind: 'hours', hours: 4, windowHours: 5 })).toMatch(/next one/);
    expect(validateForm({ ...defaultForm(), scheduleKind: 'cron', cron: 'cron(0 4 * *)' })).toMatch(/six fields/);
    expect(validateForm({ ...defaultForm(), type: 'webhook', url: 'http://x' })).toMatch(/https/);
    expect(validateForm({ ...defaultForm(), type: 'postgresql', strategy: 'alternating-users' })).toMatch(/admin secret/);
  });
});

describe('labels', () => {
  it('describes schedules', () => {
    expect(scheduleLabel({ afterDays: 30 })).toBe('Every 30 days');
    expect(scheduleLabel({ expression: 'rate(1 day)' })).toBe('Every 1 day');
    expect(scheduleLabel({ expression: 'rate(6 hours)', duration: '2h' })).toBe('Every 6 hours · 2h window');
    expect(scheduleLabel({ expression: 'cron(0 4 ? * MON *)' })).toBe('cron(0 4 ? * MON *)');
  });

  it('picks a badge for each state', () => {
    expect(statusBadge(status({ enabled: false }))).toEqual({ tone: 'neutral', text: 'Off' });
    expect(statusBadge(status({ mode: 'lambda', due: true })).text).toBe('Due · schedule only');
    expect(statusBadge(status({ status: 'failed' })).tone).toBe('danger');
    expect(statusBadge(status({ status: 'retrying' })).text).toBe('Retrying');
    expect(statusBadge(status({ status: 'running' })).text).toBe('Rotating');
    expect(statusBadge(status({ due: true })).text).toBe('Due');
    expect(statusBadge(status({ status: 'succeeded' }))).toEqual({ tone: 'success', text: 'On' });
  });
});
