<!-- Cycles system → light → dark. "System" removes data-theme so CSS follows
     the OS preference. -->
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

  const label = $derived(`Theme: ${choice}. Click to change.`);
</script>

<button type="button" class="btn-icon" aria-label={label} title={label} onclick={cycle}>
  <Icon name={choice === 'light' ? 'sun' : choice === 'dark' ? 'moon' : 'monitor'} />
</button>
