<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';
  type Props = HTMLButtonAttributes & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; href?: string; children: Snippet };
  let { variant = 'secondary', size = 'md', href, children, type = 'button', ...rest }: Props = $props();
</script>
{#if href}<a class="btn {variant} {size}" {href} {...rest as HTMLAnchorAttributes}>{@render children()}</a>
{:else}<button class="btn {variant} {size}" {type} {...rest}>{@render children()}</button>{/if}
<style>
  .btn { display: inline-flex; align-items: center; justify-content: center; gap: var(--s2); border: 1px solid var(--border); border-radius: var(--r-control); background: var(--panel-2); color: var(--text); font-weight: 600; padding: 8px 14px; line-height: 1.3; text-decoration: none; white-space: nowrap; }
  .sm { padding: 5px 10px; font-size: var(--text-sm); }
  .btn:hover:not(:disabled) { border-color: var(--muted); color: var(--text); }
  .primary { background: var(--gold); border-color: var(--gold); color: var(--on-gold); font-weight: 700; }
  .primary:hover:not(:disabled) { background: var(--gold-strong); border-color: var(--gold-strong); color: var(--on-gold); }
  .ghost { background: transparent; border-color: transparent; color: var(--muted); }
  .danger { background: transparent; border-color: var(--danger-line); color: var(--sev-critical); }
  .btn:disabled { opacity: .55; cursor: not-allowed; }
</style>
