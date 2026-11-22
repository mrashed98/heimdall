<script lang="ts">
  import type { Snippet } from 'svelte';
  let { label, trigger, align = 'start', children }: { label: string; trigger: Snippet; align?: 'start' | 'end'; children: Snippet } = $props();
  let el = $state<HTMLDetailsElement>();
</script>
<svelte:window onclick={(e) => { if (el?.open && !el.contains(e.target as Node)) el.open = false; }} onkeydown={(e) => { if (e.key === 'Escape' && el) el.open = false; }} />
<details class="menu" bind:this={el}><summary aria-label={label}>{@render trigger()}</summary><div class="pop {align}">{@render children()}</div></details>
<style>
  .menu { position: relative; }
  summary { list-style: none; } summary::-webkit-details-marker { display: none; }
  .pop { position: absolute; z-index: 20; min-width: 220px; max-height: 60vh; overflow: auto; background: var(--panel); border: 1px solid var(--border); border-radius: var(--r-panel); padding: var(--s3); box-shadow: 0 16px 40px var(--shadow); margin-top: 6px; }
  .start { left: 0; } .end { right: 0; }
</style>
