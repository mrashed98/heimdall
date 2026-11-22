<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, actions, flush = false, children }: { title?: string; actions?: Snippet; flush?: boolean; children: Snippet } = $props();
</script>
<section class="panel">
  {#if title || actions}<header><h2>{title}</h2>{#if actions}<div class="actions">{@render actions()}</div>{/if}</header>{/if}
  <div class:body={!flush}>{@render children()}</div>
</section>
<style>
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--r-panel); min-width: 0; overflow: hidden; }
  header { display: flex; justify-content: space-between; align-items: center; gap: var(--s3); padding: 10px var(--s4); border-bottom: 1px solid var(--border); }
  h2 { font-size: var(--text-lg); margin: 0; }
  .actions { display: flex; gap: var(--s2); align-items: center; color: var(--muted); font-size: var(--text-sm); }
  .body { padding: var(--s3) var(--s4); }
</style>
