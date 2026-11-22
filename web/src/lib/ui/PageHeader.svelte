<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, description, crumbs, actions }: { title: string; description?: string; crumbs?: Snippet; actions?: Snippet } = $props();
</script>
<header class="ph">
  <div class="text">{#if crumbs}<div class="crumbs">{@render crumbs()}</div>{/if}<h1>{title}</h1>{#if description}<p>{description}</p>{/if}</div>
  {#if actions}<div class="actions">{@render actions()}</div>{/if}
</header>
<style>
  .ph { display: flex; justify-content: space-between; align-items: flex-end; gap: var(--s4); flex-wrap: wrap; margin-bottom: var(--s4); }
  .text { min-width: 0; }
  h1 { font-size: var(--text-xl); margin: 0; line-height: 1.25; overflow-wrap: anywhere; }
  p { color: var(--muted); font-size: var(--text-sm); margin: 2px 0 0; }
  .crumbs { color: var(--muted); font-size: var(--text-sm); margin-bottom: 4px; }
  .actions { display: flex; gap: var(--s2); flex-wrap: wrap; align-items: center; }
</style>
