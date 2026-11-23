<script lang="ts">
  import { onMount, untrack, type Snippet } from 'svelte';
  import { api } from './api';
  import { defaultFilters, filtersFromSearch, filtersSearch, findingsUrl, packageLabel, rowTitle, views, viewFilters, type Filters } from './findings';
  import { EmptyState, ErrorState, Input, IssueRow, Logo, PageHeader, Pagination, Panel, Select, Skeleton, SubNav } from './ui';
  type Row = { id:number; kind:string; realm:string; service:string|null; purl:string|null; component_name?:string; component_version?:string; epss?:number; epss_percentile?:number; ref_id:string|null; severity:string; opened_at:string; summary?:string; fix?:string; details:Record<string, unknown> };
  let { realms, navigate, realmPicker }: { realms:string[]; navigate:(to:string)=>void; realmPicker:Snippet } = $props();

  function viewFromSearch(search: string) { const id = new URLSearchParams(search).get('view') ?? 'feed'; return views.some(v => v.id === id) ? id : 'feed'; }
  let view = $state(viewFromSearch(location.search));
  // Filters live in the URL (so Back from a finding restores them); a view's preset fills keys the URL leaves out.
  function initial(search: string): Filters {
    const f = filtersFromSearch(search); const q = new URLSearchParams(search);
    for (const [k, v] of Object.entries(viewFilters(viewFromSearch(search)))) if (!q.has(k)) (f as Record<string, unknown>)[k] = v;
    return f;
  }
  let filters = $state<Filters>(initial(location.search));
  let rows = $state<Row[]>([]); let loading = $state(true); let failed = $state(false); let revision = $state(0);
  let url = $derived(findingsUrl(filters, realms));
  let current = $derived(views.find(v => v.id === view)!);

  onMount(() => {
    const sync = () => { view = viewFromSearch(location.search); filters = initial(location.search); };
    window.addEventListener('popstate', sync); return () => window.removeEventListener('popstate', sync);
  });
  let realmKey = untrack(() => realms.join(','));
  $effect(() => { const key = realms.join(','); if (key !== realmKey) { realmKey = key; filters.offset = 0; } });
  $effect(() => { const s = filtersSearch(filters, location.search); if (s !== location.search) history.replaceState({}, '', location.pathname + s); });
  $effect(() => { const target = url; revision; let active = true; loading = true; failed = false; api<Row[]>(target).then(d => { if (active) { rows = d; loading = false; } }).catch(() => { if (active) { failed = true; loading = false; } }); return () => { active = false; }; });

  function viewHref(id: string) { const q = new URLSearchParams(); if (realms.length) q.set('realms', realms.join(',')); if (id !== 'feed') q.set('view', id); return '/findings' + (q.size ? `?${q}` : ''); }
  function pickView(e: MouseEvent, id: string) { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); view = id; filters = { ...defaultFilters, ...viewFilters(id) }; history.pushState({}, '', viewHref(id)); }
  function changeFilter() { filters.offset = 0; }
  function changeSort(value: string) { const [sort, order] = value.split(':'); filters.sort = sort!; filters.order = order!; filters.offset = 0; }
  function open(e: MouseEvent, id: number) { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); navigate(`/findings/${id}${location.search}`); }
  const sorts = [['severity:desc', 'Severity'], ['epss:desc', 'Exploit likelihood'], ['opened_at:desc', 'Newest'], ['opened_at:asc', 'Oldest'], ['advisory:asc', 'Advisory'], ['service:asc', 'Service']];
</script>

<div class="findings">
  <SubNav label="Finding views">
    {#snippet header()}<Logo size={24} wordmark />{/snippet}
    {#each ['Views', 'Watch'] as group}
      <div class="group">{group}</div>
      {#each views.filter(v => v.group === group) as v}<a class="link" href={viewHref(v.id)} aria-current={view === v.id ? 'page' : undefined} onclick={(e) => pickView(e, v.id)}>{v.label}</a>{/each}
    {/each}
  </SubNav>
  <main class="feed">
    <PageHeader title={current.label} description={current.group === 'Watch' ? 'What the watchers found for components you run' : 'Open vulnerabilities and risks across your realms'}>{#snippet actions()}{@render realmPicker()}{/snippet}</PageHeader>
    <div class="filters" aria-label="Finding filters">
      <div class="search"><Input label="Search" hideLabel type="search" placeholder="Search advisory, alias or package" bind:value={filters.search} oninput={changeFilter} /></div>
      <Select label="Severity" hideLabel bind:value={filters.severity} onchange={changeFilter}><option value="">All severities</option><option value="critical,high">Critical & high</option>{#each ['critical', 'high', 'medium', 'low', 'unknown'] as s}<option value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>{/each}</Select>
      <Select label="Kind" hideLabel bind:value={filters.kind} onchange={changeFilter}><option value="">All kinds</option>{#each [['vuln', 'Vulnerability'], ['fixavailable', 'Fix available'], ['k8scve', 'Kubernetes CVE'], ['majorrelease', 'Major release'], ['releasenotecve', 'CVE in release notes'], ['eol', 'End of life'], ['oathexpired', 'Oath expired']] as [value, label]}<option {value}>{label}</option>{/each}</Select>
      <div class="service"><Input label="Service" hideLabel placeholder="Service" bind:value={filters.service} oninput={changeFilter} /></div>
      <Select label="Fix" hideLabel bind:value={filters.has_fix} onchange={changeFilter}><option value="">Fix: any</option><option value="true">Fix available</option><option value="false">No fix yet</option></Select>
      <Select label="Status" hideLabel bind:value={filters.view_status} onchange={changeFilter}><option value="open">Open</option><option value="snoozed">Snoozed</option><option value="ignored">Ignored</option><option value="resolved">Resolved</option></Select>
      <Select label="Sort" hideLabel value={`${filters.sort}:${filters.order}`} onchange={(e) => changeSort(e.currentTarget.value)}>{#each sorts as [value, label]}<option {value}>Sort: {label}</option>{/each}</Select>
    </div>
    <Panel flush>
      <div class="head" aria-hidden="true"><span>Finding</span><span>Exploit likelihood</span><span>Severity</span></div>
      {#if loading}<Skeleton rows={6} label="Loading findings" />
      {:else if failed}<ErrorState retry={() => revision++} />
      {:else if !rows.length}<EmptyState title="Nothing matches" body={filters.view_status === 'open' && view === 'feed' ? 'No open findings in these realms. All quiet at the Bifröst.' : 'No findings match these filters.'} />
      {:else}
        {#each rows as row (row.id)}
          <IssueRow href={`/findings/${row.id}${location.search}`} onclick={(e) => open(e, row.id)} title={rowTitle(row)} sub={packageLabel(row)} fix={row.fix} meta={[row.ref_id ?? '', row.service ?? '', row.realm, `opened ${row.opened_at.slice(0, 10)}`]} epss={row.epss} epssPercentile={row.epss_percentile} severity={row.severity} />
        {/each}
      {/if}
      {#if !failed && !loading}<Pagination offset={filters.offset} count={rows.length} {loading} change={(n) => { filters.offset = n; window.scrollTo(0, 0); }} />{/if}
    </Panel>
  </main>
</div>

<style>
  .findings { display: flex; min-height: 100vh; }
  .feed { flex: 1; min-width: 0; padding: 18px 24px 32px; }
  .filters { display: flex; flex-wrap: wrap; gap: var(--s2); margin-bottom: var(--s3); align-items: end; }
  .search { flex: 1 1 200px; } .service { flex: 0 1 130px; }
  .head { display: grid; grid-template-columns: minmax(0, 1fr) 150px 92px; gap: var(--s4); padding: 8px var(--s4); background: var(--panel-2); border-bottom: 1px solid var(--border); font-size: var(--text-xs); color: var(--muted); }
  .head span:last-child { text-align: right; }
  @media (max-width: 1000px) { .findings { flex-direction: column; } }
  @media (max-width: 700px) { .feed { padding: var(--s4); } .head { display: none; } }
</style>
