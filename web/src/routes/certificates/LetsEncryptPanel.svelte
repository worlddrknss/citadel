<!-- Let's Encrypt: ACME client settings, and requesting a public certificate
     with HTTP-01 (automatic) or DNS-01 (manual TXT records). -->
<script lang="ts">
  import Icon from '$lib/components/Icon.svelte';
  import CopyButton from '$lib/components/CopyButton.svelte';
  import { api, errorMessage } from '$lib/api';
  import { toast } from '$lib/stores/toast.svelte';
  import { confirm } from '$lib/stores/confirm.svelte';
  import Seg from './Seg.svelte';

  type Env = 'staging' | 'production' | 'custom';

  let {
    settings,
    settingsError,
    canRequest,
    canConfigure,
    onsaved,
    onissued
  }: {
    settings: { environment: string; directoryUrl: string; contactEmail: string } | null;
    settingsError: string;
    canRequest: boolean;
    canConfigure: boolean;
    onsaved: () => void;
    onissued: (certId?: string) => void;
  } = $props();

  // Settings form
  let env = $state<Env>('staging');
  let dirUrl = $state('');
  let email = $state('');
  let saving = $state(false);
  let settingsTouched = $state(false);

  $effect(() => {
    if (!settings) return;
    env = (['staging', 'production', 'custom'].includes(settings.environment) ? settings.environment : 'staging') as Env;
    dirUrl = settings.environment === 'custom' ? settings.directoryUrl : '';
    email = settings.contactEmail;
  });

  const dirError = $derived(env === 'custom' && !/^https:\/\/\S+$/.test(dirUrl.trim()) ? 'Enter an https:// ACME directory URL.' : '');
  const emailError = $derived(email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ? 'Enter a valid email address.' : '');

  async function save(e: SubmitEvent) {
    e.preventDefault();
    settingsTouched = true;
    if (dirError || emailError) return;
    if (env === 'production' && settings?.environment !== 'production') {
      const ok = await confirm({
        title: 'Switch to Let’s Encrypt production?',
        message: 'Production issues publicly trusted certificates and enforces strict rate limits. Test new domains against staging first.',
        confirmLabel: 'Use production'
      });
      if (!ok) return;
    }
    saving = true;
    try {
      await api.saveLetsEncryptSettings({ environment: env, directoryUrl: env === 'custom' ? dirUrl.trim() : undefined, contactEmail: email.trim() });
      toast.success("Let's Encrypt settings saved");
      onsaved();
    } catch (err) {
      toast.error(err, 'Could not save settings');
    } finally {
      saving = false;
    }
  }

  // Request form
  let method = $state<'http' | 'dns'>('http');
  let domains = $state('');
  let reqTouched = $state(false);
  let requesting = $state(false);
  let reqError = $state('');

  const domainList = $derived(domains.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean));
  const DOMAIN_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
  const domainsError = $derived.by(() => {
    if (domainList.length === 0) return 'Enter at least one domain.';
    const bad = domainList.find((d) => !DOMAIN_RE.test(d));
    if (bad) return `“${bad}” isn't a public domain name.`;
    if (method === 'http' && domainList.some((d) => d.startsWith('*.')))
      return 'Wildcards need DNS-01. Switch the challenge type or remove the wildcard.';
    return '';
  });

  // DNS-01 order in progress
  let order = $state<{ orderId: string; records: { domain: string; name: string; value: string }[] } | null>(null);
  let completing = $state(false);

  async function request(e: SubmitEvent) {
    e.preventDefault();
    reqTouched = true;
    if (domainsError) return;
    requesting = true;
    reqError = '';
    try {
      if (method === 'http') {
        const r = await api.requestLetsEncryptCert(domainList.join(','));
        toast.success(`Issued a certificate for ${domainList[0]}`);
        domains = '';
        reqTouched = false;
        onissued(r.certId);
      } else {
        order = await api.beginLetsEncryptDns(domainList.join(','));
      }
    } catch (err) {
      reqError = errorMessage(err, 'The request failed.');
    } finally {
      requesting = false;
    }
  }

  async function complete() {
    if (!order) return;
    completing = true;
    reqError = '';
    try {
      const r = await api.completeLetsEncryptDns(order.orderId);
      toast.success(`Issued a certificate for ${r.domains || domainList[0]}`);
      order = null;
      domains = '';
      reqTouched = false;
      onissued(r.certId);
    } catch (err) {
      reqError = errorMessage(err, 'Validation failed. Check the TXT records have propagated, then try again.');
    } finally {
      completing = false;
    }
  }

  async function cancelOrder() {
    const ok = await confirm({
      title: 'Abandon this DNS challenge?',
      message: 'You will need to start a new order (with new TXT values) to issue this certificate.',
      confirmLabel: 'Abandon',
      danger: true
    });
    if (ok) {
      order = null;
      reqError = '';
    }
  }
</script>

<div class="grid">
  <section class="card" aria-labelledby="le-req-title">
    <div class="card-head">
      <h2 id="le-req-title">Request a public certificate</h2>
    </div>
    <div class="card-pad">
      {#if !canRequest}
        <p class="muted small">Editors and admins can request certificates. You have read-only access.</p>
      {:else if order}
        <div class="stack-sm">
          <div class="callout callout-info" role="status">
            <Icon name="info" size={16} />
            <span>
              Publish {order.records.length === 1 ? 'this TXT record' : `these ${order.records.length} TXT records`} at your DNS provider. When
              <code>dig TXT</code> returns the value, choose <strong>Validate and issue</strong>. Records can take a few minutes to propagate.
            </span>
          </div>
          <div class="scroll">
            <table class="table">
              <caption class="sr-only">DNS records to publish</caption>
              <thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Value</th></tr></thead>
              <tbody>
                {#each order.records as rec (rec.name + rec.value)}
                  <tr>
                    <td><span class="cell"><span class="mono">{rec.name}</span><CopyButton value={rec.name} label="Copy record name" /></span></td>
                    <td><span class="badge">TXT</span></td>
                    <td><span class="cell"><span class="mono val">{rec.value}</span><CopyButton value={rec.value} label="Copy record value" /></span></td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#if reqError}
            <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{reqError}</span></div>
          {/if}
          <div class="actions">
            <button type="button" class="btn btn-ghost" onclick={cancelOrder} disabled={completing}>Abandon</button>
            <button type="button" class="btn btn-primary" onclick={complete} disabled={completing}>
              {completing ? 'Validating…' : 'Validate and issue'}
            </button>
          </div>
        </div>
      {:else}
        <form class="stack-sm" onsubmit={request} novalidate>
          <div class="field">
            <span class="field-label">Challenge</span>
            <Seg
              label="Challenge type"
              bind:value={method}
              options={[
                { value: 'http', label: 'HTTP-01 · automatic' },
                { value: 'dns', label: 'DNS-01 · manual' }
              ]}
            />
            <span class="field-hint">
              {#if method === 'http'}
                Let's Encrypt fetches <code>http://&lt;domain&gt;/.well-known/acme-challenge/…</code> from this server, so each domain must point here on port 80.
              {:else}
                You add a TXT record per domain. Works for wildcards and hosts that aren't reachable from the internet.
              {/if}
            </span>
          </div>
          <div class="field">
            <label class="field-label" for="le-domains">Domains</label>
            <input
              id="le-domains"
              class="input mono"
              bind:value={domains}
              placeholder={method === 'dns' ? 'example.com *.example.com' : 'status.example.com'}
              autocomplete="off"
              spellcheck="false"
              aria-invalid={reqTouched && !!domainsError}
              aria-describedby="le-domains-hint"
            />
            {#if reqTouched && domainsError}
              <span class="field-error" id="le-domains-hint">{domainsError}</span>
            {:else}
              <span class="field-hint" id="le-domains-hint">Separate several names with spaces or commas. The first becomes the common name.</span>
            {/if}
          </div>
          {#if settings && settings.environment !== 'production'}
            <p class="subtle small">Using the <strong>{settings.environment}</strong> directory: certificates won't be publicly trusted.</p>
          {/if}
          {#if reqError}
            <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{reqError}</span></div>
          {/if}
          <div class="actions">
            <button type="submit" class="btn btn-primary" disabled={requesting}>
              {#if requesting}{method === 'http' ? 'Requesting…' : 'Starting…'}{:else}{method === 'http' ? 'Request certificate' : 'Get DNS records'}{/if}
            </button>
          </div>
        </form>
      {/if}
    </div>
  </section>

  <section class="card" aria-labelledby="le-set-title">
    <div class="card-head">
      <h2 id="le-set-title">ACME client settings</h2>
    </div>
    <div class="card-pad">
      {#if settingsError}
        <div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{settingsError}</span></div>
      {:else if !settings}
        <div class="stack-sm" aria-busy="true"><span class="skeleton sk"></span><span class="skeleton sk"></span><span class="skeleton sk"></span></div>
      {:else}
        <form class="stack-sm" onsubmit={save} novalidate>
          <fieldset class="field" disabled={!canConfigure}>
            <legend class="field-label">Directory</legend>
            <Seg
              label="ACME directory"
              bind:value={env}
              options={[
                { value: 'staging', label: 'Staging' },
                { value: 'production', label: 'Production' },
                { value: 'custom', label: 'Custom' }
              ]}
            />
          </fieldset>
          {#if env === 'custom'}
            <div class="field">
              <label class="field-label" for="le-dir">Directory URL</label>
              <input id="le-dir" class="input mono" bind:value={dirUrl} disabled={!canConfigure} placeholder="https://acme.example.com/directory" aria-invalid={settingsTouched && !!dirError} />
              {#if settingsTouched && dirError}<span class="field-error">{dirError}</span>{/if}
            </div>
          {:else}
            <p class="subtle small mono dir">{env === settings.environment ? settings.directoryUrl : env === 'production' ? 'acme-v02.api.letsencrypt.org' : 'acme-staging-v02.api.letsencrypt.org'}</p>
          {/if}
          <div class="field">
            <label class="field-label" for="le-email">Contact email</label>
            <input id="le-email" class="input" type="email" autocomplete="email" bind:value={email} disabled={!canConfigure} placeholder="pki@example.com" aria-invalid={!!emailError} />
            {#if emailError}<span class="field-error">{emailError}</span>{:else}<span class="field-hint">Let's Encrypt sends expiry and policy notices here.</span>{/if}
          </div>
          {#if canConfigure}
            <div class="actions"><button type="submit" class="btn btn-secondary" disabled={saving}>{saving ? 'Saving…' : 'Save settings'}</button></div>
          {:else}
            <p class="subtle small">Only admins can change these settings.</p>
          {/if}
        </form>
      {/if}
    </div>
  </section>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
    gap: 20px;
    align-items: start;
  }
  @media (max-width: 1000px) {
    .grid {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .card-head h2 {
    font-family: var(--font-sans);
    font-size: var(--text-md);
    letter-spacing: 0;
  }
  .stack-sm {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .stack-sm .field + .field {
    margin-top: 0;
  }
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
  }
  legend {
    padding: 0;
    margin-bottom: 6px;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }
  .cell {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .val {
    overflow-wrap: anywhere;
  }
  .dir {
    margin: -8px 0 0;
    overflow-wrap: anywhere;
  }
  .sk {
    display: block;
    height: 14px;
  }
  p {
    margin: 0;
  }
</style>
