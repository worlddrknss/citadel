// In-console docs pages that other pages link to ("Learn more"). The unit
// test checks every anchor here exists in the Markdown, so a renamed heading
// can't silently break these links.

export const DOC_LINKS = {
  /** The step-by-step agents guide. */
  agentsGuide: '/docs/getting-started-agents',
  /** Making a secret usable by agents: the Agent access tab and usage profiles. */
  usageProfiles: '/docs/getting-started-agents#step-3-make-a-secret-usable-by-agents',
  /** Granting a credential to an agent. */
  grants: '/docs/getting-started-agents#step-4-grant-the-credential',
  /** Refusal reasons and their fixes. */
  troubleshooting: '/docs/getting-started-agents#troubleshooting'
} as const;
