<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, body, action }: { title: string; body?: string; action?: Snippet } = $props();
</script>
<div class="empty">
  <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" /><path d="M9 12l2 2 4-4" /></svg>
  <strong>{title}</strong>{#if body}<p>{body}</p>{/if}{#if action}{@render action()}{/if}
</div>
<style>
  .empty { display: grid; justify-items: center; gap: var(--s2); text-align: center; padding: 48px var(--s5); }
  svg { color: var(--gold); } strong { font-size: var(--text-lg); }
  p { color: var(--muted); max-width: 460px; margin: 0; }
</style>
