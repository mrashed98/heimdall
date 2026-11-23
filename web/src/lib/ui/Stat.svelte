<script lang="ts">
  let { label, value, tone = 'default', href }: { label: string; value: string | number; tone?: 'default' | 'ok' | 'critical' | 'gold'; href?: string } = $props();
</script>
<svelte:element this={href ? 'a' : 'div'} class="stat" {href}><span class="label">{label}</span><span class="value {tone}">{value}</span></svelte:element>
<style>
  .stat { display: grid; gap: 2px; background: var(--panel); border: 1px solid var(--border); border-radius: var(--r-panel); padding: var(--s3) var(--s4); color: var(--text); min-width: 0; }
  a.stat:hover { border-color: var(--gold-line); color: var(--text); }
  .label { color: var(--muted); font-size: var(--text-sm); }
  .value { font-size: var(--text-2xl); font-weight: 800; line-height: 1.2; }
  .ok { color: var(--ok); } .critical { color: var(--sev-critical); } .gold { color: var(--gold); }
</style>
