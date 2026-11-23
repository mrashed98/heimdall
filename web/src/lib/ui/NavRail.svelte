<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon, { type IconName } from './Icon.svelte';
  import Logo from './Logo.svelte';
  type Item = { href: string; label: string; icon: IconName; current: boolean; bottom?: boolean };
  let { items, home, navigate, footer }: { items: Item[]; home: string; navigate: (href: string) => void; footer?: Snippet } = $props();
  function go(e: MouseEvent, href: string) { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); navigate(href); }
</script>
<nav class="rail" aria-label="Primary">
  <a class="home" href={home} aria-label="Heimdall home" onclick={(e) => go(e, home)}><Logo size={36} /></a>
  {#each items as item}
    <a class="item" class:bottom={item.bottom} href={item.href} aria-current={item.current ? 'page' : undefined} onclick={(e) => go(e, item.href)}><Icon name={item.icon} /><span>{item.label}</span></a>
  {/each}
  {#if footer}<div class="footer">{@render footer()}</div>{/if}
</nav>
<style>
  .rail { position: sticky; top: 0; height: 100vh; flex: 0 0 68px; background: var(--rail); border-right: 1px solid var(--border); display: flex; flex-direction: column; align-items: center; padding: 14px 0; gap: 6px; }
  .home { margin-bottom: 14px; }
  .item { width: 56px; padding: 8px 0; border-radius: var(--r-panel); color: var(--muted); display: grid; justify-items: center; gap: 3px; font-size: 10.5px; }
  .item:hover { color: var(--text); background: var(--panel); }
  .item[aria-current='page'] { background: var(--gold-soft); color: var(--gold); font-weight: 600; }
  .bottom { margin-top: auto; }
  .footer { margin-top: 6px; }
  .item.bottom ~ .footer { margin-top: 6px; }
  .rail:not(:has(.bottom)) .footer { margin-top: auto; }
  @media (max-width: 700px) {
    .rail { position: sticky; z-index: 10; height: auto; width: 100%; flex-direction: row; padding: 6px var(--s2); border-right: 0; border-bottom: 1px solid var(--border); gap: 2px; }
    .home { margin: 0 var(--s1) 0 0; } .item { width: auto; padding: 8px; }
    /* Icon-only on phones; the label stays for screen readers. */
    .item span { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; } .bottom, .footer, .rail:not(:has(.bottom)) .footer { margin-top: 0; } .bottom { margin-left: auto; }
  }
</style>
