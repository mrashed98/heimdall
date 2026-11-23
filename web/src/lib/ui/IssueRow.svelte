<script lang="ts">
  import Badge from './Badge.svelte';
  import EpssBar from './EpssBar.svelte';
  type Props = { href: string; title: string; sub?: string; fix?: string; meta: string[]; epss?: number | null; epssPercentile?: number | null; severity: string; onclick?: (e: MouseEvent) => void };
  let { href, title, sub, fix, meta, epss, epssPercentile, severity, onclick }: Props = $props();
</script>
<a class="row" {href} {onclick}>
  <span class="main">
    <span class="title">{title}</span>
    {#if sub || fix}<span class="sub">{sub}{#if fix}{#if sub}<span class="arrow">→</span>{/if}<span class="fix">{fix}</span>{/if}</span>{/if}
    <span class="meta">{#each meta.filter(Boolean) as item}<span>{item}</span>{/each}</span>
  </span>
  <EpssBar score={epss} percentile={epssPercentile} />
  <span class="sev"><Badge {severity} /></span>
</a>
<style>
  .row { display: grid; grid-template-columns: minmax(0, 1fr) 150px 92px; gap: var(--s4); align-items: center; padding: var(--s3) var(--s4); border-bottom: 1px solid var(--border); color: var(--text); }
  .row:hover { background: var(--panel-2); color: var(--text); }
  .main { display: grid; gap: 2px; min-width: 0; }
  .title { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub { font: var(--text-sm) var(--font-mono); color: var(--muted); overflow-wrap: anywhere; }
  .arrow { margin: 0 .5ch; } .fix { color: var(--ok); }
  .meta { font-size: var(--text-xs); color: var(--muted); display: flex; flex-wrap: wrap; column-gap: 6px; }
  .meta span + span::before { content: '·'; margin-right: 6px; }
  .sev { justify-self: end; }
  @media (max-width: 700px) { .row { grid-template-columns: minmax(0, 1fr) auto; } .row :global(.epss) { display: none; } }
</style>
