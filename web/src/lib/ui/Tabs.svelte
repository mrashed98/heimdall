<script lang="ts">
  type Item = { id: string; label: string; count?: number };
  let { items, current = $bindable(), label, change }: { items: Item[]; current: string; label: string; change?: (id: string) => void } = $props();
</script>
<div class="tabs" role="tablist" aria-label={label}>
  {#each items as item}<button role="tab" aria-selected={current === item.id} onclick={() => { current = item.id; change?.(item.id); }}>{item.label}{#if item.count != null} <span class="count">{item.count}</span>{/if}</button>{/each}
</div>
<style>
  .tabs { display: flex; gap: var(--s1); border-bottom: 1px solid var(--border); overflow-x: auto; }
  button { border: 0; background: none; padding: 9px var(--s3); color: var(--muted); border-bottom: 2px solid transparent; white-space: nowrap; }
  button[aria-selected='true'] { color: var(--text); font-weight: 600; border-bottom-color: var(--gold); }
  .count { color: var(--muted); font-weight: 400; }
</style>
