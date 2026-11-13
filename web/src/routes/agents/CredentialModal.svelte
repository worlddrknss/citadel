<!--
  Usage profile editor: makes a secret usable by agents and says how (kind,
  injection) and where (hosts, methods, paths, network).
-->
<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { errorMessage } from '#lib/api.ts';
  import { toast } from '#lib/stores/toast.svelte.ts';
  import {
    agentsApi,
    isHttpKind,
    isMintedKind,
    formatPermissions,
    parsePermissions,
    splitList,
    validateCredential,
    HTTP_METHODS,
    KIND_HINTS,
    KIND_LABELS,
    type AgentCredential,
    type CredentialInput,
    type CredentialKind
  } from './api';

  let {
    open = $bindable(false),
    coord,
    credential,
    onsaved
  }: {
    open?: boolean;
    /** The secret the profile is for. */
    coord: { project: string; env: string; path: string; key: string };
    /** The profile being edited; null for a new one. */
    credential: AgentCredential | null;
    onsaved: () => void;
  } = $props();

  const kinds: CredentialKind[] = ['http_header', 'http_basic', 'http_query', 'login', 'raw', 'aws_sts', 'github_app', 'oauth2_client_credentials'];
  const uid = Math.random().toString(36).slice(2, 8);

  let name = $state('');
  let kind = $state<CredentialKind>('http_header');
  let description = $state('');
  let hosts = $state('');
  let methods = $state<string[]>(['GET']);
  let paths = $state('');
  let headerName = $state('Authorization');
  let headerPrefix = $state('Bearer ');
  let queryParam = $state('');
  let allowHttp = $state(false);
  let cidrs = $state('');
  let saving = $state(false);
  let saveError = $state('');
  // login
  let urlPatterns = $state('');
  let totpAlgorithm = $state<'' | 'SHA256' | 'SHA512'>('');
  // aws_sts
  let roleArn = $state('');
  let stsEndpoint = $state('');
  let awsRegion = $state('');
  let externalId = $state('');
  let sessionPolicy = $state('');
  let durationSeconds = $state(0);
  let signingService = $state('');
  // github_app
  let appId = $state('');
  let installationId = $state('');
  let ghBaseUrl = $state('');
  let ghRepos = $state('');
  let ghPerms = $state('');
  // oauth2_client_credentials
  let tokenUrl = $state('');
  let clientId = $state('');
  let clientAuth = $state<'' | 'basic' | 'post'>('');
  let oauthScopes = $state('');
  let audience = $state('');

  $effect(() => {
    if (!open) return;
    const c = credential;
    name = c?.name ?? coord.key.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 63);
    kind = c?.kind ?? 'http_header';
    description = c?.description ?? '';
    hosts = (c?.allowedHosts ?? []).join('\n');
    methods = c ? [...c.allowedMethods] : ['GET'];
    paths = (c?.allowedPathPrefixes ?? []).join('\n');
    headerName = c?.headerName ?? 'Authorization';
    headerPrefix = c ? (c.headerPrefix ?? '') : 'Bearer ';
    queryParam = c?.queryParam ?? '';
    allowHttp = c?.allowHttp ?? false;
    cidrs = (c?.allowedCidrs ?? []).join('\n');
    urlPatterns = (c?.login?.urlPatterns ?? []).join('\n');
    totpAlgorithm = c?.login?.totpAlgorithm ?? '';
    roleArn = c?.awsSts?.roleArn ?? '';
    stsEndpoint = c?.awsSts?.endpoint ?? '';
    awsRegion = c?.awsSts?.region ?? '';
    externalId = c?.awsSts?.externalId ?? '';
    sessionPolicy = c?.awsSts?.sessionPolicy ?? '';
    durationSeconds = c?.awsSts?.durationSeconds ?? 0;
    signingService = c?.awsSts?.signingService ?? '';
    appId = c?.githubApp?.appId ?? '';
    installationId = c?.githubApp?.installationId ? String(c.githubApp.installationId) : '';
    ghBaseUrl = c?.githubApp?.baseUrl ?? '';
    ghRepos = (c?.githubApp?.repositories ?? []).join('\n');
    ghPerms = formatPermissions(c?.githubApp?.permissions);
    tokenUrl = c?.oauth2?.tokenUrl ?? '';
    clientId = c?.oauth2?.clientId ?? '';
    clientAuth = c?.oauth2?.clientAuth ?? '';
    oauthScopes = (c?.oauth2?.scopes ?? []).join(' ');
    audience = c?.oauth2?.audience ?? '';
    saveError = '';
  });

  const brokerable = $derived(isHttpKind(kind) || isMintedKind(kind));
  const permsParsed = $derived(parsePermissions(ghPerms));

  const input = $derived<CredentialInput>({
    name: name.trim(),
    ...(credential ? {} : { project: coord.project, env: coord.env, path: coord.path, key: coord.key }),
    kind,
    description: description.trim(),
    allowedHosts: kind === 'login' ? [] : splitList(hosts.toLowerCase()),
    allowedMethods: brokerable ? methods : [],
    allowedPathPrefixes: splitList(paths),
    headerName: kind === 'http_header' ? headerName.trim() : '',
    headerPrefix: kind === 'http_header' ? headerPrefix : '',
    queryParam: kind === 'http_query' ? queryParam.trim() : '',
    allowHttp: brokerable && allowHttp,
    allowedCidrs: splitList(cidrs),
    ...(kind === 'login' ? { login: { urlPatterns: splitList(urlPatterns), totpAlgorithm } } : {}),
    ...(kind === 'aws_sts'
      ? {
          awsSts: {
            roleArn: roleArn.trim(),
            endpoint: stsEndpoint.trim(),
            region: awsRegion.trim(),
            externalId: externalId.trim(),
            sessionPolicy: sessionPolicy.trim(),
            durationSeconds: Number(durationSeconds) || 0,
            signingService: signingService.trim()
          }
        }
      : {}),
    ...(kind === 'github_app'
      ? {
          githubApp: {
            appId: appId.trim(),
            installationId: Number(installationId) || 0,
            baseUrl: ghBaseUrl.trim(),
            repositories: splitList(ghRepos),
            permissions: permsParsed ?? {}
          }
        }
      : {}),
    ...(kind === 'oauth2_client_credentials'
      ? { oauth2: { tokenUrl: tokenUrl.trim(), clientId: clientId.trim(), clientAuth, scopes: splitList(oauthScopes), audience: audience.trim() } }
      : {})
  });
  const formError = $derived(
    kind === 'github_app' && permsParsed === null ? 'Permissions: one name=read|write|admin per line.' : validateCredential(input)
  );

  function toggleMethod(m: string, on: boolean) {
    methods = on ? [...methods, m] : methods.filter((x) => x !== m);
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (saving || formError) return;
    saving = true;
    saveError = '';
    try {
      if (credential) await agentsApi.updateCredential(input);
      else await agentsApi.createCredential(input);
      toast.success(credential ? 'Usage profile saved' : `Agents can now be granted ${input.name}`);
      open = false;
      onsaved();
    } catch (err) {
      saveError = errorMessage(err, 'Could not save the usage profile.');
    } finally {
      saving = false;
    }
  }
</script>

<Modal bind:open title={credential ? `Edit ${credential.name}` : 'Make usable by agents'} description="Agents refer to the credential by name. Citadel only ever sends it where this profile allows." size="md">
  <form id="cred-form-{uid}" class="form" onsubmit={save} novalidate>
    {#if saveError}<div class="callout callout-danger" role="alert"><Icon name="alert-circle" size={16} /><span>{saveError}</span></div>{/if}
    <div class="field">
      <label class="field-label" for="cr-name-{uid}">Credential name</label>
      <input id="cr-name-{uid}" class="input mono" bind:value={name} disabled={!!credential} spellcheck="false" placeholder="github-pat" />
    </div>
    <div class="field">
      <label class="field-label" for="cr-kind-{uid}">How agents use it</label>
      <select id="cr-kind-{uid}" class="select" bind:value={kind}>
        {#each kinds as k (k)}<option value={k}>{KIND_LABELS[k]}</option>{/each}
      </select>
      <span class="field-hint">{KIND_HINTS[kind]}</span>
    </div>
    {#if kind === 'http_header'}
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-hn-{uid}">Header</label>
          <input id="cr-hn-{uid}" class="input mono" bind:value={headerName} spellcheck="false" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-hp-{uid}">Value prefix</label>
          <input id="cr-hp-{uid}" class="input mono" bind:value={headerPrefix} spellcheck="false" placeholder="none" />
        </div>
      </div>
    {:else if kind === 'http_query'}
      <div class="field">
        <label class="field-label" for="cr-qp-{uid}">Query parameter</label>
        <input id="cr-qp-{uid}" class="input mono" bind:value={queryParam} spellcheck="false" placeholder="api_key" />
      </div>
    {:else if kind === 'login'}
      <div class="field">
        <label class="field-label" for="cr-urls-{uid}">Pages the login may be used on</label>
        <textarea id="cr-urls-{uid}" class="input mono" rows="2" bind:value={urlPatterns} spellcheck="false" placeholder="https://app.example.com/login&#10;https://*.example.com"></textarea>
        <span class="field-hint">One per line: https://host[:port][/path]. Agents get the username and password only for a page under one of these.</span>
      </div>
      <div class="field">
        <label class="field-label" for="cr-totp-{uid}">TOTP algorithm for a bare seed</label>
        <select id="cr-totp-{uid}" class="select" bind:value={totpAlgorithm}>
          <option value="">From the otpauth:// URI</option>
          <option value="SHA256">SHA-256</option>
          <option value="SHA512">SHA-512</option>
        </select>
        <span class="field-hint">SHA-1 seeds can't be used: Citadel runs in FIPS 140-3 mode, where HMAC-SHA-1 is not approved.</span>
      </div>
    {:else if kind === 'aws_sts'}
      <div class="field">
        <label class="field-label" for="cr-arn-{uid}">Role to assume</label>
        <input id="cr-arn-{uid}" class="input mono" bind:value={roleArn} spellcheck="false" placeholder="arn:aws:iam::123456789012:role/agent-deploy" />
      </div>
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-svc-{uid}">Sign requests for service <span class="subtle">(optional)</span></label>
          <input id="cr-svc-{uid}" class="input mono" bind:value={signingService} spellcheck="false" placeholder="s3" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-reg-{uid}">Region</label>
          <input id="cr-reg-{uid}" class="input mono" bind:value={awsRegion} spellcheck="false" placeholder="us-east-1" />
        </div>
      </div>
      <details class="adv">
        <summary>Session</summary>
        <div class="field">
          <label class="field-label" for="cr-pol-{uid}">Session policy <span class="subtle">(optional; then grants can't add one)</span></label>
          <textarea id="cr-pol-{uid}" class="input mono" rows="3" bind:value={sessionPolicy} spellcheck="false" placeholder={'{"Version":"2012-10-17","Statement":[…]}'}></textarea>
        </div>
        <div class="row2">
          <div class="field">
            <label class="field-label" for="cr-dur-{uid}">Session length</label>
            <select id="cr-dur-{uid}" class="select" bind:value={durationSeconds}>
              <option value={0}>1 hour (default)</option>
              <option value={900}>15 minutes</option>
              <option value={7200}>2 hours</option>
              <option value={43200}>12 hours</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label" for="cr-ext-{uid}">External ID <span class="subtle">(optional)</span></label>
            <input id="cr-ext-{uid}" class="input mono" bind:value={externalId} spellcheck="false" />
          </div>
        </div>
        <div class="field">
          <label class="field-label" for="cr-sts-{uid}">STS endpoint <span class="subtle">(optional)</span></label>
          <input id="cr-sts-{uid}" class="input mono" bind:value={stsEndpoint} spellcheck="false" placeholder="https://sts.amazonaws.com/" />
        </div>
      </details>
    {:else if kind === 'github_app'}
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-app-{uid}">App ID</label>
          <input id="cr-app-{uid}" class="input mono" bind:value={appId} spellcheck="false" placeholder="123456" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-inst-{uid}">Installation ID</label>
          <input id="cr-inst-{uid}" class="input mono" inputmode="numeric" bind:value={installationId} spellcheck="false" />
        </div>
      </div>
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-repos-{uid}">Default repositories</label>
          <textarea id="cr-repos-{uid}" class="input mono" rows="2" bind:value={ghRepos} spellcheck="false" placeholder="api&#10;web"></textarea>
        </div>
        <div class="field">
          <label class="field-label" for="cr-perms-{uid}">Default permissions</label>
          <textarea id="cr-perms-{uid}" class="input mono" rows="2" bind:value={ghPerms} spellcheck="false" placeholder="contents=read&#10;pull_requests=write"></textarea>
        </div>
      </div>
      <span class="field-hint">Grants may narrow these. Without defaults, every grant must name repositories or permissions: Citadel never issues installation-wide tokens.</span>
      <div class="field">
        <label class="field-label" for="cr-ghurl-{uid}">API base URL <span class="subtle">(GitHub Enterprise Server only)</span></label>
        <input id="cr-ghurl-{uid}" class="input mono" bind:value={ghBaseUrl} spellcheck="false" placeholder="https://github.example.com/api/v3" />
      </div>
    {:else if kind === 'oauth2_client_credentials'}
      <div class="field">
        <label class="field-label" for="cr-turl-{uid}">Token endpoint</label>
        <input id="cr-turl-{uid}" class="input mono" bind:value={tokenUrl} spellcheck="false" placeholder="https://auth.example.com/oauth/token" />
      </div>
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-cid-{uid}">Client ID</label>
          <input id="cr-cid-{uid}" class="input mono" bind:value={clientId} spellcheck="false" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-cauth-{uid}">Client authentication</label>
          <select id="cr-cauth-{uid}" class="select" bind:value={clientAuth}>
            <option value="">HTTP basic (default)</option>
            <option value="post">In the request body</option>
          </select>
        </div>
      </div>
      <div class="row2">
        <div class="field">
          <label class="field-label" for="cr-scopes-{uid}">Scopes <span class="subtle">(optional)</span></label>
          <input id="cr-scopes-{uid}" class="input mono" bind:value={oauthScopes} spellcheck="false" placeholder="read write" />
        </div>
        <div class="field">
          <label class="field-label" for="cr-aud-{uid}">Audience <span class="subtle">(optional)</span></label>
          <input id="cr-aud-{uid}" class="input mono" bind:value={audience} spellcheck="false" />
        </div>
      </div>
    {/if}
    {#if kind !== 'login'}
      <div class="field">
        <label class="field-label" for="cr-hosts-{uid}">Allowed hosts{isHttpKind(kind) ? '' : ' (optional)'}</label>
        <textarea id="cr-hosts-{uid}" class="input mono" rows="2" bind:value={hosts} spellcheck="false" placeholder="api.github.com&#10;*.example.com"></textarea>
        <span class="field-hint">One per line. Exact hosts or *.example.com; add :port for a non-default port.{isMintedKind(kind) ? ' Brokered requests with the minted token may only go here.' : ''}</span>
      </div>
    {/if}
    {#if brokerable}
      <fieldset class="field plain">
        <legend class="field-label">Allowed methods</legend>
        <div class="methods">
          {#each HTTP_METHODS as m (m)}
            <label class="check-inline"><input type="checkbox" checked={methods.includes(m)} onchange={(e) => toggleMethod(m, e.currentTarget.checked)} /><span class="mono">{m}</span></label>
          {/each}
        </div>
      </fieldset>
      <div class="field">
        <label class="field-label" for="cr-paths-{uid}">Path prefixes <span class="subtle">(optional)</span></label>
        <textarea id="cr-paths-{uid}" class="input mono" rows="2" bind:value={paths} spellcheck="false" placeholder="/repos/acme/"></textarea>
      </div>
      <details class="adv">
        <summary>Network</summary>
        <label class="check-inline"><input type="checkbox" bind:checked={allowHttp} /><span>Allow plain http:// (otherwise https only)</span></label>
        <div class="field">
          <label class="field-label" for="cr-cidr-{uid}">Private networks allowed <span class="subtle">(optional)</span></label>
          <textarea id="cr-cidr-{uid}" class="input mono" rows="2" bind:value={cidrs} spellcheck="false" placeholder="10.20.0.0/16"></textarea>
          <span class="field-hint">Loopback, link-local, private and metadata addresses are refused unless listed here.</span>
        </div>
      </details>
    {/if}
    <div class="field">
      <label class="field-label" for="cr-desc-{uid}">Description <span class="subtle">(optional; agents see it)</span></label>
      <input id="cr-desc-{uid}" class="input" bind:value={description} placeholder="GitHub API for the acme org" />
    </div>
    {#if formError && name}<span class="field-error" role="status">{formError}</span>{/if}
  </form>
  {#snippet footer()}
    <button type="button" class="btn btn-ghost" onclick={() => (open = false)}>Cancel</button>
    <button type="submit" form="cred-form-{uid}" class="btn btn-primary" disabled={saving || !!formError}>{saving ? 'Saving…' : 'Save'}</button>
  {/snippet}
</Modal>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form .field + .field {
    margin-top: 0;
  }
  .row2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: var(--space-3);
  }
  .row2 .field + .field {
    margin-top: 0;
  }
  .plain {
    border: 0;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .methods {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
  }
  .check-inline {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-base);
  }
  .adv {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .adv summary {
    cursor: pointer;
    font-weight: 600;
    font-size: var(--text-sm);
    margin-bottom: var(--space-2);
  }
  .adv .field {
    margin-top: var(--space-3);
  }
  @media (max-width: 560px) {
    .row2 {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
