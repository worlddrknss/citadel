import { fireEvent, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { tick } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { confirm, confirmState } from '#lib/stores/confirm.svelte.ts';
import { toast } from '#lib/stores/toast.svelte.ts';
import ConfirmHost from './ConfirmHost.svelte';
import SecretValue from './SecretValue.svelte';
import Tabs from './Tabs.svelte';

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  for (const t of toast.items) toast.dismiss(t.id);
  confirmState.settle(false);
});

describe('SecretValue', () => {
  it('reveals on demand, counts down, then hides itself', async () => {
    vi.useFakeTimers();
    const load = vi.fn(async () => 's3cr3t');
    render(SecretValue, { load, hideAfter: 3 });
    expect(screen.getByLabelText('Hidden value')).toBeInTheDocument();
    expect(load).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole('button', { name: 'Reveal value' }));
    await vi.waitFor(() => expect(screen.getByText('s3cr3t')).toBeInTheDocument());
    expect(load).toHaveBeenCalledTimes(1);
    expect(screen.getByText('Hides in 3 s')).toBeInTheDocument();

    await vi.advanceTimersByTimeAsync(1000);
    expect(screen.getByText('Hides in 2 s')).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(2000);
    expect(screen.queryByText('s3cr3t')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reveal value' })).toBeInTheDocument();
    // The interval is gone once hidden.
    expect(vi.getTimerCount()).toBe(0);
  });

  it('hide button hides immediately; the next reveal fetches again', async () => {
    const load = vi.fn(async () => 'v');
    render(SecretValue, { load });
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal value' }));
    await screen.findByText('v');
    await fireEvent.click(screen.getByRole('button', { name: 'Hide value' }));
    expect(screen.queryByText('v')).not.toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal value' }));
    await screen.findByText('v');
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('a failed reveal toasts and stays masked', async () => {
    render(SecretValue, { load: async () => Promise.reject(new Error('denied by policy')) });
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal value' }));
    await vi.waitFor(() => expect(toast.items.map((t) => t.message)).toContain('denied by policy'));
    expect(screen.getByLabelText('Hidden value')).toBeInTheDocument();
  });

  it('copies without revealing, then clears the clipboard if unchanged', async () => {
    vi.useFakeTimers();
    let clip = '';
    const clipboard = {
      writeText: vi.fn(async (t: string) => {
        clip = t;
      }),
      readText: vi.fn(async () => clip)
    };
    vi.stubGlobal('navigator', { ...navigator, clipboard });
    const load = vi.fn(async () => 'copied-value');
    render(SecretValue, { load });

    await fireEvent.click(screen.getByRole('button', { name: 'Copy value' }));
    await vi.waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith('copied-value'));
    expect(screen.queryByText('copied-value')).not.toBeInTheDocument();
    await tick();
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(toast.items.at(-1)?.message).toMatch(/Clipboard clears in 30 s/);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(clip).toBe('');
  });

  it('leaves the clipboard alone if the user copied something else meanwhile', async () => {
    vi.useFakeTimers();
    let clip = '';
    const clipboard = {
      writeText: vi.fn(async (t: string) => {
        clip = t;
      }),
      readText: vi.fn(async () => clip)
    };
    vi.stubGlobal('navigator', { ...navigator, clipboard });
    render(SecretValue, { load: async () => 'x' });
    await fireEvent.click(screen.getByRole('button', { name: 'Copy value' }));
    await vi.waitFor(() => expect(clip).toBe('x'));
    clip = 'something else';
    await vi.advanceTimersByTimeAsync(30_000);
    expect(clip).toBe('something else');
  });
});

describe('ConfirmHost', () => {
  it('resolves true on confirm and false on cancel', async () => {
    const user = userEvent.setup();
    render(ConfirmHost);
    const p = confirm({ title: 'Disable key?', message: 'Callers will fail.', confirmLabel: 'Disable' });
    await tick();
    expect(screen.getByRole('heading', { name: 'Disable key?' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Disable' }));
    await expect(p).resolves.toBe(true);
    await tick();
    expect(screen.queryByRole('heading', { name: 'Disable key?' })).not.toBeInTheDocument();

    const q = confirm({ title: 'Again?', message: '' });
    await tick();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await expect(q).resolves.toBe(false);
  });

  it('typeToConfirm blocks confirming until the exact text is typed', async () => {
    const user = userEvent.setup();
    render(ConfirmHost);
    const p = confirm({ title: 'Delete project', message: 'Gone for good.', danger: true, confirmLabel: 'Delete', typeToConfirm: 'payments' });
    await tick();
    const btn = screen.getByRole('button', { name: 'Delete' });
    expect(btn).toBeDisabled();
    expect(btn).toHaveClass('btn-danger');

    const input = screen.getByRole('textbox');
    await user.type(input, 'payment');
    expect(btn).toBeDisabled();
    // Enter submits the form, but must not confirm while blocked.
    await user.keyboard('{Enter}');
    expect(confirmState.pending).not.toBeNull();
    await user.type(input, 'sX');
    expect(btn).toBeDisabled();
    await user.clear(input);
    await user.type(input, 'Payments');
    expect(btn).toBeDisabled();
    await user.clear(input);
    await user.type(input, 'payments');
    expect(btn).toBeEnabled();
    await user.keyboard('{Enter}');
    await expect(p).resolves.toBe(true);
  });

  it('clears the typed text when a new confirmation opens', async () => {
    const user = userEvent.setup();
    render(ConfirmHost);
    void confirm({ title: 'First', message: '', typeToConfirm: 'abc' });
    await tick();
    await user.type(screen.getByRole('textbox'), 'abc');
    void confirm({ title: 'Second', message: '', typeToConfirm: 'abc' });
    await tick();
    expect(screen.getByRole('textbox')).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled();
  });
});

describe('Tabs', () => {
  const tabs = [
    { id: 'a', label: 'Alpha' },
    { id: 'b', label: 'Beta', count: 3 },
    { id: 'c', label: 'Gamma' }
  ];

  it('marks the active tab and uses a roving tabindex', () => {
    render(Tabs, { tabs, active: 'b', label: 'Sections' });
    expect(screen.getByRole('tablist', { name: 'Sections' })).toBeInTheDocument();
    const [a, b, c] = screen.getAllByRole('tab');
    expect(b).toHaveAttribute('aria-selected', 'true');
    expect(a).toHaveAttribute('aria-selected', 'false');
    expect(b).toHaveAttribute('tabindex', '0');
    expect(a).toHaveAttribute('tabindex', '-1');
    expect(c).toHaveAttribute('tabindex', '-1');
    expect(b).toHaveTextContent(/^Beta\s*3$/);
  });

  it('arrow keys, Home and End move selection and focus, wrapping around', async () => {
    const user = userEvent.setup();
    const onchange = vi.fn();
    render(Tabs, { tabs, active: 'a', label: 'Sections', onchange });
    const [a, b, c] = screen.getAllByRole('tab');
    a.focus();
    await user.keyboard('{ArrowRight}');
    expect(b).toHaveAttribute('aria-selected', 'true');
    expect(b).toHaveFocus();
    await user.keyboard('{ArrowRight}{ArrowRight}');
    expect(a).toHaveAttribute('aria-selected', 'true');
    expect(a).toHaveFocus();
    await user.keyboard('{ArrowLeft}');
    expect(c).toHaveAttribute('aria-selected', 'true');
    expect(c).toHaveFocus();
    await user.keyboard('{Home}');
    expect(a).toHaveFocus();
    await user.keyboard('{End}');
    expect(c).toHaveFocus();
    expect(onchange.mock.calls.map((x) => x[0])).toEqual(['b', 'c', 'a', 'c', 'a', 'c']);
  });

  it('click selects', async () => {
    const user = userEvent.setup();
    const onchange = vi.fn();
    render(Tabs, { tabs, active: 'a', label: 'Sections', onchange });
    await user.click(screen.getByRole('tab', { name: 'Gamma' }));
    expect(screen.getByRole('tab', { name: 'Gamma' })).toHaveAttribute('aria-selected', 'true');
    expect(onchange).toHaveBeenCalledWith('c');
  });
});
