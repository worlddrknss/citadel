<!-- Cycles system → light → dark. "System" removes data-theme so CSS follows
     the OS preference. app.html applies a saved choice before first paint. -->
<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';

  type Choice = 'system' | 'light' | 'dark';
  let choice = $state<Choice>('system');

  onMount(() => {
    try {
      const t = localStorage.getItem('citadel-theme');
      choice = t === 'light' || t === 'dark' ? t : 'system';
    } catch {
      /* storage blocked: stay on system */
    }
  });

  function cycle() {
    choice = choice === 'system' ? 'light' : choice === 'light' ? 'dark' : 'system';
    const root = document.documentElement;
    if (choice === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', choice);
    try {
      if (choice === 'system') localStorage.removeItem('citadel-theme');
      else localStorage.setItem('citadel-theme', choice);
    } catch {
      /* not persisted; fine */
    }
  }

  const next = $derived(choice === 'system' ? 'light' : choice === 'light' ? 'dark' : 'system');
  const label = $derived(`Switch theme (now ${choice}, next ${next})`);
</script>

<button type="button" class="btn btn-ghost btn-icon theme-toggle" aria-label={label} title={label} onclick={cycle}>
  <Icon name={choice === 'light' ? 'sun' : choice === 'dark' ? 'moon' : 'monitor'} />
</button>

<style>
  .theme-toggle {
    width: var(--ctl-h);
    height: var(--ctl-h);
    border-radius: var(--radius-md);
  }
</style>
