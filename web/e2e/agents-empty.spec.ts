import { expect, open, test } from './fixtures';
import { AGENT_ID, fixtures } from './mock';

// With no agent credentials in the account, the grants tab says how to add
// one instead of only disabling the button. This empties a shared fixture, so
// it lives in its own file and never runs alongside the other agent tests.

test('grants tab explains how to add a credential when there are none', async ({ page }) => {
  const saved = fixtures.agentCredentials.splice(0, fixtures.agentCredentials.length);
  try {
    await open(page, `/agents/${AGENT_ID}?tab=grants`);
    const hint = page.getByRole('note');
    await expect(hint).toContainText('no agent credentials to grant yet');
    await expect(hint.getByRole('link', { name: 'Secrets' })).toHaveAttribute('href', /\/secrets$/);
    await expect(page.getByRole('button', { name: 'Grant credential' })).toBeDisabled();
  } finally {
    fixtures.agentCredentials.push(...saved);
  }
});
