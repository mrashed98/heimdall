<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  type Props = HTMLInputAttributes & { label: string; hint?: string; error?: string; hideLabel?: boolean; value?: string };
  let { label, hint, error, hideLabel = false, value = $bindable(''), ...rest }: Props = $props();
</script>
<label class="field"><span class:sr={hideLabel}>{label}</span><input bind:value aria-invalid={error ? true : undefined} {...rest} />{#if hint}<small>{hint}</small>{/if}{#if error}<small class="error" role="alert">{error}</small>{/if}</label>
<style>
  .field { display: grid; gap: 6px; font-size: var(--text-sm); font-weight: 600; color: var(--muted); min-width: 0; }
  input { width: 100%; border: 1px solid var(--border); background: var(--bg); color: var(--text); border-radius: var(--r-control); padding: 8px 11px; font-weight: 400; font-size: var(--text-md); }
  input:focus { border-color: var(--gold); outline: none; }
  small { font-weight: 400; } .error { color: var(--sev-high); }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
