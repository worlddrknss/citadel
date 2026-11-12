// Promise-based confirmation: `if (await confirm({...})) doIt()`. One dialog
// host lives in the layout, so pages no longer each carry a copy of the
// confirm-modal state and markup.

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  /** Styles the confirm button as destructive. */
  danger?: boolean;
  /**
   * The user must type this exact text before confirming. Use it for
   * irreversible actions: force delete, deleting an account, bulk deletes.
   */
  typeToConfirm?: string;
}

interface Pending extends ConfirmOptions {
  resolve: (ok: boolean) => void;
}

function createConfirm() {
  let pending = $state<Pending | null>(null);

  function ask(opts: ConfirmOptions): Promise<boolean> {
    pending?.resolve(false);
    return new Promise((resolve) => {
      pending = { ...opts, resolve };
    });
  }

  function settle(ok: boolean) {
    pending?.resolve(ok);
    pending = null;
  }

  return {
    get pending() {
      return pending;
    },
    ask,
    settle
  };
}

export const confirmState = createConfirm();
export const confirm = (opts: ConfirmOptions) => confirmState.ask(opts);
