<script lang="ts">
  import type { Snippet } from 'svelte';
  let { children, label }: { children: Snippet, label: string } = $props();
</script>
<div class="table-wrap"><table aria-label={label}>{@render children()}</table></div>
<style>
 .table-wrap { overflow:auto; max-height:32rem; border-top:1px solid var(--border); } table { width:100%; border-collapse:collapse; text-align:left; font-size:.9rem; } :global(th) { position:sticky; top:0; background:var(--page); z-index:1; color:var(--muted); font-size:.75rem; } :global(th), :global(td) { padding:.85rem .7rem; border-bottom:1px solid var(--border); } :global(th button) { border:0; background:none; padding:0; font-weight:700; color:inherit; } 
</style>
