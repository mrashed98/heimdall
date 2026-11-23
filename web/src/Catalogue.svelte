<script lang="ts">
  // Living catalogue of the component library. Served at /design in dev builds only.
  import { Badge, Button, DataTable, EmptyState, EpssBar, ErrorState, Input, IssueRow, Logo, PageHeader, Pagination, Panel, Pill, RealmPicker, Select, Skeleton, Stat, Tabs } from './lib/ui';
  let tab = $state('active'); let text = $state(''); let sel = $state(''); let realms = $state<string[]>([]);
  const swatches = ['bg', 'rail', 'panel', 'panel-2', 'border', 'text', 'muted', 'gold', 'gold-soft', 'sky', 'ok', 'sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-unknown'];
</script>
<main class="cat">
  <PageHeader title="Design system" description="Every component in web/src/lib/ui, styled only by tokens.css. Toggle the theme to check both palettes.">
    {#snippet crumbs()}<Logo size={28} wordmark />{/snippet}
  </PageHeader>
  <h2>Colour</h2>
  <div class="swatches">{#each swatches as s}<div><span style:background="var(--{s})"></span><code>--{s}</code></div>{/each}</div>
  <h2>Button · Badge · Pill</h2>
  <div class="row"><Button variant="primary">Primary</Button><Button>Secondary</Button><Button variant="ghost">Ghost</Button><Button variant="danger">Danger</Button><Button size="sm">Small</Button><Button disabled>Disabled</Button></div>
  <div class="row">{#each ['critical', 'high', 'medium', 'low', 'unknown'] as s}<Badge severity={s} />{/each}<Pill tone="gold">admin · all realms</Pill><Pill>homelab</Pill><Pill mono>is:open</Pill></div>
  <h2>Inputs</h2>
  <div class="row"><Input label="Search" placeholder="Advisory, alias or package" bind:value={text} /><Input label="With error" error="Give a reason for this oath." /><Select label="Severity" bind:value={sel}><option value="">All</option><option>critical</option></Select><RealmPicker realms={['homelab', 'prod']} selected={realms} change={(r) => realms = r} /></div>
  <h2>Data</h2>
  <div class="grid"><Stat label="Open findings" value={670} /><Stat label="Fix available" value={660} tone="ok" /><Stat label="Likely exploited" value={34} tone="critical" /><div><EpssBar score={0.944} percentile={0.999} /><EpssBar score={0.003} percentile={0.52} /><EpssBar /></div></div>
  <Panel title="IssueRow inside a flush Panel" flush>
    <IssueRow href="#" title="Remote code execution in Log4j" sub="log4j-core 2.14.1" fix="2.15.0" meta={['GHSA-jfh8-c2jp-5v3q', 'search-indexer', 'homelab', 'opened 2026-11-21']} epss={0.944} epssPercentile={0.999} severity="critical" />
    <IssueRow href="#" title="lodash 4 → 5 is out" meta={['majorrelease', 'web', 'prod']} severity="unknown" />
    <Pagination offset={0} count={2} loading={false} change={() => {}} />
  </Panel>
  <h2>Tabs · Table</h2>
  <Tabs label="Oath status" bind:current={tab} items={[{ id: 'active', label: 'Active', count: 0 }, { id: 'past', label: 'Expired / revoked', count: 3 }]} />
  <Panel flush><DataTable label="Example"><thead><tr><th aria-sort="ascending"><button>Service</button></th><th>Realm</th><th>Findings</th></tr></thead><tbody><tr><td>search-indexer</td><td>homelab</td><td>144</td></tr></tbody></DataTable></Panel>
  <h2>States</h2>
  <div class="grid"><Panel><EmptyState title="No oaths sworn" body="Explain why it is empty and what to do next." /></Panel><Panel><ErrorState retry={() => {}} /></Panel><Panel><Skeleton rows={3} /></Panel></div>
</main>
<style>
  .cat { padding: var(--s5); max-width: 1200px; display: grid; gap: var(--s4); }
  h2 { font-size: var(--text-sm); text-transform: uppercase; letter-spacing: .1em; color: var(--muted); margin: var(--s4) 0 0; }
  .row { display: flex; gap: var(--s3); flex-wrap: wrap; align-items: end; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: var(--s3); }
  .swatches { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: var(--s3); }
  .swatches span { display: block; height: 44px; border-radius: var(--r-control); border: 1px solid var(--border); }
  code { font-size: var(--text-xs); color: var(--muted); }
</style>
