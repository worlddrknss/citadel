// Toast notifications. Each toast owns its own timer, so a new message is
// never cleared early by an older one's timeout (the old per-page `flash`
// pattern did exactly that).

import { errorMessage } from '#lib/api.ts';

export type ToastKind = 'success' | 'error' | 'info';
export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

const DURATION: Record<ToastKind, number> = { success: 4000, info: 5000, error: 8000 };

function createToasts() {
  let items = $state<Toast[]>([]);
  let nextId = 1;
  const timers = new Map<number, ReturnType<typeof setTimeout>>();

  function dismiss(id: number) {
    clearTimeout(timers.get(id));
    timers.delete(id);
    items = items.filter((t) => t.id !== id);
  }

  function push(kind: ToastKind, message: string) {
    const id = nextId++;
    items = [...items.slice(-4), { id, kind, message }];
    timers.set(
      id,
      setTimeout(() => dismiss(id), DURATION[kind])
    );
    return id;
  }

  return {
    get items() {
      return items;
    },
    dismiss,
    success: (message: string) => push('success', message),
    info: (message: string) => push('info', message),
    error: (e: unknown, fallback?: string) =>
      push('error', typeof e === 'string' ? e : errorMessage(e, fallback))
  };
}

export const toast = createToasts();
