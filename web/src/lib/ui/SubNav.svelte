<script lang="ts">
  import type { Snippet } from 'svelte';
  let { label, header, children }: { label: string; header?: Snippet; children: Snippet } = $props();
</script>
<nav class="subnav" aria-label={label}>{#if header}<div class="header">{@render header()}</div>{/if}{@render children()}</nav>
<style>
  .subnav { flex: 0 0 212px; background: var(--panel); border-right: 1px solid var(--border); padding: var(--s4) 10px; display: flex; flex-direction: column; gap: 2px; min-height: 100vh; position: sticky; top: 0; align-self: flex-start; overflow-y: auto; max-height: 100vh; }
  .header { padding: 2px 10px 14px; }
  .subnav :global(.group) { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); padding: 14px 10px 4px; }
  .subnav :global(.link) { display: flex; justify-content: space-between; gap: var(--s2); padding: 7px 10px; border-radius: var(--r-control); color: var(--muted); }
  .subnav :global(.link:hover) { color: var(--text); background: var(--panel-2); }
  .subnav :global(.link[aria-current='page']) { background: var(--panel-2); color: var(--text); font-weight: 600; }
  .subnav :global(.link .n) { font-size: var(--text-xs); color: var(--muted); font-weight: 400; }
  @media (max-width: 1000px) { .subnav { min-height: 0; max-height: none; position: static; flex: 1 1 100%; flex-direction: row; flex-wrap: wrap; border-right: 0; border-bottom: 1px solid var(--border); padding: var(--s2); } .header { display: none; } .subnav :global(.group) { flex-basis: 100%; padding: 6px 10px 2px; } }
</style>
