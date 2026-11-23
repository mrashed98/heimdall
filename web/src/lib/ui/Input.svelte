<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  type Props = HTMLInputAttributes & { label: string; hint?: string; error?: string; hideLabel?: boolean; value?: string };
  let { label, hint, error, hideLabel = false, value = $bindable(''), id, ...rest }: Props = $props();
  const generated = $props.id(); const uid = $derived(id ?? generated);
</script>
<div class="field"><label for={uid}><span class:sr={hideLabel}>{label}</span></label><input id={uid} bind:value aria-invalid={error ? true : undefined} aria-describedby={[hint && `${uid}-hint`, error && `${uid}-error`].filter(Boolean).join(' ') || undefined} {...rest} />{#if hint}<small id="{uid}-hint">{hint}</small>{/if}{#if error}<small id="{uid}-error" class="error" role="alert">{error}</small>{/if}</div>
<style>
  .field { display: grid; gap: 6px; font-size: var(--text-sm); font-weight: 600; color: var(--muted); min-width: 0; }
  input { width: 100%; border: 1px solid var(--border); background: var(--bg); color: var(--text); border-radius: var(--r-control); padding: 8px 11px; font-weight: 400; font-size: var(--text-md); }
  input:focus-visible { border-color: var(--gold); outline: 2px solid var(--gold-line); outline-offset: 1px; }
  small { font-weight: 400; } .error { color: var(--sev-high); }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
