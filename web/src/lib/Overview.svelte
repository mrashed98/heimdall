<script lang="ts">
  import { api } from './api';
  import { statusUrl } from './overview';
  import { SEVERITIES as severities, type Severity } from './ui/format';
  import { packageLabel, rowTitle } from './findings';
  import { dailySeries, TREND_DAYS, type TrendRow } from './trends';
  import TrendChart from './TrendChart.svelte';
  import { Badge, DataTable, EmptyState, EpssBar, ErrorState, Panel, Skeleton, Stat } from './ui';
  let { realms, navigate }: { realms: string[]; navigate: (to: string) => void } = $props();
  type Counts = { realm: string; severity: Severity; count: number };
  type Risk = { realm: string; service: string; critical: number; high: number; medium: number; risk: number };
  type Status = { severity: Counts[]; fix_available: number; services: Risk[]; eol: { realm: string; service: string | null; ref_id: string | null; details: Record<string, unknown> }[]; sync: Record<string, string | null> };
  type Release = { id: number; target: string; version: string; published_at: string | null; notes_class: string | null };
  type Fixable = { id: number; kind: string; ref_id: string | null; summary?: string; component_name?: string; component_version?: string; fix?: string; service: string | null; realm: string; severity: string; epss?: number; epss_percentile?: number; details: Record<string, unknown> };
  let status = $state<Status | null>(null); let releases = $state<Release[]>([]); let fixFirst = $state<Fixable[]>([]); let trend = $state<TrendRow[] | null>([]); let fixFailed = $state(false);
  let loading = $state(true); let failed = $state(false); let revision = $state(0);
  let groups = $derived([...new Set((status?.severity ?? []).map(x => x.realm))].map(realm => ({ realm, counts: severities.map(s => status?.severity.find(x => x.realm === realm && x.severity === s)?.count ?? 0) })));
  let bySeverity = (s: Severity) => (status?.severity ?? []).filter(x => x.severity === s).reduce((n, x) => n + x.count, 0);
  let total = $derived((status?.severity ?? []).reduce((n, row) => n + row.count, 0));
  let max = $derived(Math.max(1, ...groups.map(g => g.counts.reduce((a, b) => a + b, 0))));
  let days = $derived(dailySeries(trend ?? [], TREND_DAYS));
  let recorded = $derived(days.filter(d => d.critical !== null));
  let q = $derived(realms.length ? `?realms=${encodeURIComponent(realms.join(','))}` : '');
  function date(value: string | null) { if (!value) return 'Not yet'; const d = new Date(value); return Number.isNaN(d.getTime()) ? 'Not yet' : d.toLocaleString(); }
  function go(e: MouseEvent, to: string) { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); navigate(to); }
  $effect(() => {
    const url = statusUrl(realms); const realmParam = realms.length ? `&realms=${encodeURIComponent(realms.join(','))}` : ''; revision;
    let active = true; loading = true; failed = false;
    // The fix-first list is optional: if it fails, only that panel is empty.
    Promise.all([api<Status>(url), api<Release[]>('/api/v1/releases?limit=5'), api<Fixable[]>(`/api/v1/findings?ui=true&kind=fixavailable&view_status=open&sort=epss&order=desc&limit=5${realmParam}`).catch(() => null), api<TrendRow[]>(`/api/v1/trends?days=${TREND_DAYS}${realmParam}`).catch(() => null)])
      .then(([s, r, f, t]) => { if (active) { status = s; releases = r; fixFirst = f ?? []; fixFailed = f === null; trend = t; loading = false; } })
      .catch(() => { if (active) { failed = true; loading = false; } });
    return () => { active = false; };
  });
</script>
{#if loading && !status}<Skeleton rows={5} label="Loading overview" />
{:else if failed}<Panel><ErrorState retry={() => revision++} /></Panel>
{:else if status}
  <div class="overview">
    <div class="stats">
      <Stat label="Open findings" value={total} href={'/findings' + q} />
      <Stat label="Critical" value={bySeverity('critical')} tone={bySeverity('critical') ? 'critical' : 'default'} href={'/findings?severity=critical' + (q ? '&' + q.slice(1) : '')} />
      <Stat label="High" value={bySeverity('high')} />
      <Stat label="Fix available" value={status.fix_available} tone="ok" href={'/findings?view=fix' + (q ? '&' + q.slice(1) : '')} />
    </div>
    <div class="two">
      <Panel title="Open findings by realm">
        {#if total === 0}<EmptyState title="All quiet at the Bifröst" body="No open findings in these realms." />
        {:else}
          <div class="legend">{#each severities as s}<Badge severity={s} />{/each}</div>
          {#each groups as g}
            <div class="bar-row"><strong>{g.realm}</strong>
              <div class="bar" role="img" aria-label={`${g.realm}: ${g.counts.map((c, i) => `${severities[i]} ${c}`).join(', ')}`}>{#each g.counts as c, i}{#if c}<span class={severities[i]} style:width="{c / max * 100}%"></span>{/if}{/each}</div>
              <span class="muted small">{g.counts.reduce((a, b) => a + b, 0)}</span>
            </div>
          {/each}
        {/if}
      </Panel>
      <Panel title="Fix first" flush>
        {#snippet actions()}Most likely exploited, with a fix{/snippet}
        {#if fixFirst.length}
          <ul class="list">{#each fixFirst as f}<li><a href={`/findings/${f.id}${q}`} onclick={(e) => go(e, `/findings/${f.id}${q}`)}><span class="t">{rowTitle(f)}</span><span class="mono small">{packageLabel(f)}{#if f.fix}<span class="arrow">→</span><b class="ok">{f.fix}</b>{/if}</span></a><EpssBar score={f.epss} percentile={f.epss_percentile} /></li>{/each}</ul>
        {:else if fixFailed}<p class="pad muted">This list could not be loaded.</p>
        {:else}<p class="pad muted">Nothing with a fix is open.</p>{/if}
      </Panel>
    </div>
    <Panel title={`Open findings over ${TREND_DAYS} days`}>
      {#snippet actions()}Last count each day, UTC{/snippet}
      {#if trend === null}<p class="muted small">Trend data could not be loaded.</p>
      {:else if recorded.length}
        <div class="trends">
          {#each [['critical', 'Critical', 'var(--sev-critical)'], ['high', 'High', 'var(--sev-high)']] as const as [s, label, color]}
            <div><h3>{label}</h3><TrendChart {label} {color} points={days.map(d => ({ day: d.day, value: d[s] }))} /></div>
          {/each}
        </div>
        <details><summary>Show as table</summary>
          <DataTable label="Open findings per day"><thead><tr><th>Day</th>{#each severities as s}<th>{s[0]!.toUpperCase() + s.slice(1)}</th>{/each}</tr></thead>
            <tbody>{#each [...days].reverse() as d}<tr><td>{d.day}</td>{#each severities as s}<td>{d[s] ?? '—'}</td>{/each}</tr>{/each}</tbody></DataTable>
        </details>
      {:else}<p class="muted small">The first point appears after the next matcher run; a line after two days.</p>{/if}
    </Panel>
    <Panel title="Riskiest services" flush>
      {#snippet actions()}Critical × 10 + High × 3 + Medium{/snippet}
      {#if status.services.length}
        <DataTable label="Riskiest services"><thead><tr><th>Service</th><th>Realm</th><th>Critical</th><th>High</th><th>Medium</th><th>Risk</th></tr></thead>
          <tbody>{#each status.services as s}<tr><td><strong>{s.service}</strong></td><td>{s.realm}</td><td class="crit">{s.critical}</td><td>{s.high}</td><td>{s.medium}</td><td><strong>{s.risk}</strong></td></tr>{/each}</tbody></DataTable>
      {:else}<p class="pad muted">No services with open findings.</p>{/if}
    </Panel>
    <div class="three">
      <Panel title="Latest releases" flush>
        {#if releases.length}<ul class="kv">{#each releases as r}<li><span><strong>{r.target}</strong> <span class="mono">{r.version}</span></span><span class="muted small">{r.published_at ? date(r.published_at) : 'Date unknown'}{r.notes_class ? ` · ${r.notes_class}` : ''}</span></li>{/each}</ul>
        {:else}<p class="pad muted">No releases recorded yet.</p>{/if}
      </Panel>
      <Panel title="Feed health" flush>
        <ul class="kv">{#each [['osv', 'OSV'], ['nvd', 'NVD'], ['k8s', 'Kubernetes feed'], ['epss', 'EPSS'], ['sight', 'Sight (cluster inventory)'], ['sight-docker', 'Sight for Docker']].filter(([id]) => id !== 'sight-docker' || id in (status?.sync ?? {})) as [id, label]}<li><span><span class="dot" class:fresh={!!status.sync[id]}></span>{label}</span><span class="muted small">{date(status.sync[id] ?? null)}</span></li>{/each}</ul>
      </Panel>
      <Panel title="End of life" flush>
        {#if status.eol.length}<ul class="kv">{#each status.eol as w}<li><strong>{typeof w.details.target === 'string' ? w.details.target : (w.ref_id ?? 'End-of-life warning')}</strong><span class="muted small">{w.realm}{w.service ? ` / ${w.service}` : ''}{typeof w.details.eol === 'string' ? ` · ${w.details.eol}` : ''}</span></li>{/each}</ul>
        {:else}<p class="pad muted">Nothing you run is past end of life.</p>{/if}
      </Panel>
    </div>
  </div>
{/if}
<style>
  .overview { display: grid; gap: var(--s4); }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: var(--s3); }
  .two { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: var(--s4); }
  .three { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--s4); }
  .legend { display: flex; gap: var(--s2); flex-wrap: wrap; margin-bottom: var(--s3); }
  .bar-row { display: grid; grid-template-columns: 110px minmax(0, 1fr) 48px; gap: var(--s3); align-items: center; padding: 6px 0; }
  .bar { display: flex; height: 12px; border-radius: 6px; overflow: hidden; background: var(--panel-2); }
  .bar .critical { background: var(--sev-critical); } .bar .high { background: var(--sev-high); } .bar .medium { background: var(--sev-medium); } .bar .low { background: var(--sev-low); } .bar .unknown { background: var(--sev-unknown); }
  .list, .kv { list-style: none; margin: 0; padding: 0; }
  .list li { display: grid; grid-template-columns: minmax(0, 1fr) 140px; gap: var(--s3); align-items: center; padding: 9px var(--s4); border-bottom: 1px solid var(--border); }
  .list a { display: grid; gap: 2px; color: var(--text); min-width: 0; } .list a:hover .t { color: var(--gold); }
  .t { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kv li { display: flex; justify-content: space-between; gap: var(--s3); padding: 9px var(--s4); border-bottom: 1px solid var(--border); }
  .kv li > span:last-child { text-align: right; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--sev-unknown); margin-right: var(--s2); } .dot.fresh { background: var(--ok); }
  .mono { font-family: var(--font-mono); } .small { font-size: var(--text-sm); } .muted { color: var(--muted); } .ok { color: var(--ok); font-weight: 600; } .arrow { margin: 0 .5ch; } .crit { color: var(--sev-critical); font-weight: 700; }
  .pad { padding: var(--s3) var(--s4); margin: 0; }
  .trends { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--s5); }
  .trends h3 { margin: 0 0 var(--s2); font-size: var(--text-sm); font-weight: 600; color: var(--muted); }
  details { margin-top: var(--s3); font-size: var(--text-sm); } summary { cursor: pointer; color: var(--muted); margin-bottom: var(--s2); }
  @media (max-width: 1000px) { .two { grid-template-columns: 1fr; } }
  @media (max-width: 700px) { .list li { grid-template-columns: 1fr; } .kv li { flex-direction: column; gap: 2px; } .kv li > span:last-child { text-align: left; } }
</style>
