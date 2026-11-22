<script lang="ts">
  import { api } from './api';
  import { severities, statusUrl, type Severity } from './overview';
  import AllQuiet from './illustrations/AllQuiet.svelte';
  import SeverityBadge from './components/SeverityBadge.svelte';
  import Table from './components/Table.svelte';
  import Skeleton from './components/Skeleton.svelte';
  import EmptyState from './components/EmptyState.svelte';
  import RetryState from './components/RetryState.svelte';
  let { realms }: { realms: string[] } = $props();
  type Counts = { realm: string, severity: Severity, count: number };
  type Risk = { realm: string, service: string, critical: number, high: number, medium: number, risk: number };
  type Status = { severity: Counts[], fix_available: number, services: Risk[], eol: {realm:string, service:string | null, ref_id:string | null, details: Record<string, unknown>}[], sync: Record<string, string | null> };
  type Release = { id:number, target:string, version:string, published_at:string | null, notes_class:string | null };
  let status = $state<Status | null>(null); let releases = $state<Release[]>([]); let loading = $state(true); let failed = $state(false); let revision = $state(0);
  let sort = $state<'risk' | 'service' | 'realm'>('risk'); let ascending = $state(false);
  let rows = $derived([...(status?.services ?? [])].sort((a,b) => { const comparison = sort === 'risk' ? a.risk - b.risk : a[sort].localeCompare(b[sort]); return (ascending ? 1 : -1) * comparison; }));
  let groups = $derived([...new Set((status?.severity ?? []).map(x => x.realm))].map(realm => ({realm, counts: severities.map(severity => status?.severity.find(x => x.realm === realm && x.severity === severity)?.count ?? 0)})));
  let total = $derived((status?.severity ?? []).reduce((n, row) => n + row.count, 0));
  let max = $derived(Math.max(1, ...groups.map(g => g.counts.reduce((a,b) => a+b,0))));
  function date(value: string | null) { if (!value) return 'Not yet recorded'; const d = new Date(value); return Number.isNaN(d.getTime()) ? 'Not yet recorded' : d.toLocaleString(); }
  function changeSort(field: 'risk' | 'service' | 'realm') { if (sort === field) ascending = !ascending; else { sort = field; ascending = field !== 'risk'; } }
  $effect(() => {
    const url = statusUrl(realms); revision;
    let active = true; loading = true; failed = false;
    Promise.all([api<Status>(url), api<Release[]>('/api/v1/releases?limit=5')]).then(([s, r]) => { if (active) { status = s; releases = r; loading = false; } }).catch(() => { if (active) { failed = true; loading = false; } });
    return () => { active = false; };
  });
</script>
{#if loading}<Skeleton />{:else if failed}<RetryState retry={() => revision++} />{:else if status}
  <div class="overview">
    <section class="findings"><div class="section-heading"><div><p class="kicker">THE WATCH</p><h2>Open findings</h2><p>Risk across your selected realms</p></div><div class="fix"><strong>{status.fix_available}</strong><span>Fix available</span></div></div>
      {#if total === 0}<div class="quiet"><AllQuiet /><p>No open findings in these realms.</p></div>{:else}
        <div class="legend">{#each severities as severity}<SeverityBadge {severity} />{/each}</div>
        <div class="bars">{#each groups as group}<div class="bar-row"><strong>{group.realm}</strong><div><svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">{#each group.counts as count, i}<rect x={group.counts.slice(0,i).reduce((a,b) => a+b,0) / max * 100} y="0" width={count / max * 100} height="8" class={severities[i]} />{/each}</svg><div class="counts">{#each group.counts as count, i}<span>{severities[i]}: {count}</span>{/each}</div></div></div>{/each}</div>
      {/if}
    </section>
    <section><p class="kicker">PRIORITY</p><h2>Services by risk</h2><p>Critical × 10 + High × 3 + Medium. Top 10 services.</p>
      {#if rows.length}<Table label="Top services by risk"><thead><tr><th aria-sort={sort === 'service' ? (ascending ? 'ascending' : 'descending') : 'none'}><button onclick={() => changeSort('service')}>Service ↕</button></th><th aria-sort={sort === 'realm' ? (ascending ? 'ascending' : 'descending') : 'none'}><button onclick={() => changeSort('realm')}>Realm ↕</button></th><th>Critical / High / Medium</th><th aria-sort={sort === 'risk' ? (ascending ? 'ascending' : 'descending') : 'none'}><button onclick={() => changeSort('risk')}>Risk ↕</button></th></tr></thead><tbody>{#each rows as row}<tr><td>{row.service}</td><td>{row.realm}</td><td>{row.critical} / {row.high} / {row.medium}</td><td><strong>{row.risk}</strong></td></tr>{/each}</tbody></Table>{:else}<EmptyState message="No services with open findings." />{/if}
    </section>
    <div class="lower"><section><p class="kicker">WATCHERS / RELEASES</p><h2>Latest releases</h2><p>Updates from watched projects</p>{#if releases.length}<ul>{#each releases as release}<li><div><strong>{release.target}</strong> <code>{release.version}</code></div><span>{release.published_at ? date(release.published_at) : 'Date unknown'}{release.notes_class ? ` · ${release.notes_class}` : ''}</span></li>{/each}</ul>{:else}<EmptyState message="No releases recorded yet." />{/if}</section>
      <section><p class="kicker">FEED HEALTH</p><h2>Last sync</h2><p>Most recent successful refresh</p><ul>{#each [['osv','OSV'],['nvd','NVD'],['k8s','Kubernetes feed'],['epss','EPSS'],['sight','Sight: live cluster inventory']] as [id,label]}<li><strong>{label}</strong><span>{date(status.sync[id])}</span></li>{/each}</ul></section></div>
    {#if status.eol.length}<section><p class="kicker">LIFECYCLE</p><h2>End-of-life warnings</h2><p>Latest 10 warnings in your realms</p><ul>{#each status.eol as warning}<li><strong>{typeof warning.details.target === 'string' ? warning.details.target : (warning.ref_id ?? 'End-of-life warning')}</strong><span>{warning.realm}{warning.service ? ` / ${warning.service}` : ''} {typeof warning.details.eol === 'string' ? `· ${warning.details.eol}` : ''}</span></li>{/each}</ul></section>{/if}
  </div>
{/if}
<style>
 .overview { margin-top:3rem; max-width:1200px; display:grid; gap:3rem; } section { min-width:0; } h2 { font-size:1.3rem; letter-spacing:-.02em; margin:.25rem 0; } section > p:not(.kicker), .section-heading p:not(.kicker) { color:var(--muted); margin:.35rem 0 1.25rem; } .kicker { color:var(--accent-high); font-weight:700; font-size:.7rem; letter-spacing:.12em; margin:0; } .section-heading { display:flex; justify-content:space-between; gap:1rem; align-items:start; } .fix { border-left:2px solid var(--fix); padding-left:1rem; display:grid; min-width:110px; } .fix strong { font-size:2rem; line-height:1; } .fix span { color:var(--muted); font-size:.8rem; margin-top:.4rem; } .legend { display:flex; flex-wrap:wrap; gap:1rem; align-items:center; margin:1.5rem 0; } .bars { display:grid; gap:1.5rem; } .bar-row { display:grid; grid-template-columns:minmax(90px, 150px) 1fr; gap:1rem; } svg { display:block; width:100%; height:24px; background:var(--surface); } rect.critical { fill:var(--critical); } rect.high { fill:var(--high); opacity:.65; } rect.medium { fill:var(--medium); } rect.low { fill:var(--low); } rect.unknown { fill:var(--unknown); } .counts { display:flex; gap:.7rem; flex-wrap:wrap; margin-top:.4rem; color:var(--muted); font-size:.75rem; text-transform:capitalize; } .lower { display:grid; grid-template-columns:1fr 1fr; gap:3rem; } ul { padding:0; margin:0; list-style:none; border-top:1px solid var(--border); } li { display:flex; justify-content:space-between; gap:1rem; padding:.8rem 0; border-bottom:1px solid var(--border); font-size:.9rem; } li span { color:var(--muted); text-align:right; } code { font-family:var(--font-mono); } .quiet { display:flex; align-items:center; gap:2rem; color:var(--muted); } .quiet :global(svg) { background:none; width:160px; height:auto; } @media(max-width:700px) { .lower { grid-template-columns:1fr; gap:2rem; } .bar-row { grid-template-columns:1fr; gap:.4rem; } li { flex-direction:column; gap:.25rem; } li span { text-align:left; } }
</style>
