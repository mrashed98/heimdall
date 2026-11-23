<script lang="ts">
  import type { Snippet } from 'svelte';
  let { tone = 'neutral', mono = false, children }: { tone?: 'neutral' | 'gold'; mono?: boolean; children: Snippet } = $props();
</script>
<span class="pill {tone}" class:mono>{@render children()}</span>
<style>
  .pill { display: inline-flex; align-items: center; gap: var(--s1); border: 1px solid var(--border); background: var(--panel-2); border-radius: 999px; padding: 1px 10px; font-size: var(--text-sm); white-space: nowrap; }
  .gold { border-color: var(--gold-line); background: var(--gold-soft); color: var(--gold); border-radius: var(--r-badge); font-weight: 600; padding: 1px 8px; }
  .mono { font-family: var(--font-mono); }
</style>
