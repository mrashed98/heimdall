<script lang="ts">
  import type { Snippet } from 'svelte';
  let { label, children }: { label: string; children: Snippet } = $props();
</script>
<div class="wrap"><table aria-label={label}>{@render children()}</table></div>
<style>
  .wrap { overflow: auto; }
  table { width: 100%; border-collapse: collapse; text-align: left; font-size: var(--text-md); }
  .wrap :global(th) { position: sticky; top: 0; z-index: 1; background: var(--panel-2); color: var(--muted); font-size: var(--text-xs); font-weight: 600; }
  .wrap :global(th), .wrap :global(td) { padding: 9px var(--s4); border-bottom: 1px solid var(--border); vertical-align: top; }
  .wrap :global(tbody tr:hover) { background: var(--panel-2); }
  .wrap :global(th button) { border: 0; background: none; padding: 0; font-weight: 600; color: inherit; }
  .wrap :global(th[aria-sort='ascending'] button::after) { content: ' ↑'; } .wrap :global(th[aria-sort='descending'] button::after) { content: ' ↓'; }
</style>
