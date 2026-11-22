<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLSelectAttributes } from 'svelte/elements';
  type Props = HTMLSelectAttributes & { label: string; hideLabel?: boolean; value?: string; children: Snippet };
  let { label, hideLabel = false, value = $bindable(''), children, ...rest }: Props = $props();
</script>
<label class="field"><span class:sr={hideLabel}>{label}</span><select bind:value {...rest}>{@render children()}</select></label>
<style>
  .field { display: grid; gap: 6px; font-size: var(--text-sm); font-weight: 600; color: var(--muted); min-width: 0; }
  select { border: 1px solid var(--border); background: var(--panel); color: var(--text); border-radius: var(--r-control); padding: 7px 10px; font-weight: 500; font-size: var(--text-md); }
  select:focus { border-color: var(--gold); outline: none; }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
