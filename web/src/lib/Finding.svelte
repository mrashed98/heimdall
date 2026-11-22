<script lang="ts">
  import { api, ApiError, type Grant } from './api';
  import { advisoryLinks, canEdit, epssLabel, nearestFix, rowTitle, validateOath } from './findings';
  import { Badge, Button, EmptyState, EpssBar, ErrorState, Icon, Input, PageHeader, Panel, Pill, Select, Skeleton, Stat } from './ui';
  type Oath = { id: number; kind: string; reason: string; status: string; created_by: string; created_at: string; expires_at: string | null; review_at: string | null };
  type Detail = { kind: string; severity: string; ref_id: string | null; status: string; opened_at: string; realm: string; service: string | null; summary: string | null; aliases: string[]; scores: Record<string, number> | null; epss: number | null; epss_percentile: number | null; fixed: Record<string, string[]> | null; name_key: string | null; version: string | null; purl: string | null; affected: { service: string; digest: string | null; image: string | null }[]; oaths: Oath[] };
  let { id, grants, navigate }: { id: number; grants: Grant[]; navigate: (to: string) => void } = $props();

  let detail = $state<Detail | null>(null); let loading = $state(true); let failed = $state(false); let missing = $state(false); let revision = $state(0);
  let affectedOffset = $state(0); let oathsOffset = $state(0);
  let kind = $state('snooze'); let until = $state(''); let reason = $state(''); let allRealms = $state(false); let error = $state(''); let busy = $state(false); let copied = $state(false);

  $effect(() => { id; affectedOffset = 0; oathsOffset = 0; error = ''; });
  $effect(() => {
    const target = `/api/v1/findings/${id}?affected_offset=${affectedOffset}&oaths_offset=${oathsOffset}`; revision;
    let active = true; loading = true; failed = false; missing = false;
    api<Detail>(target).then(d => { if (active) { detail = d; loading = false; } }).catch(e => { if (active) { if (e instanceof ApiError && e.status === 404) missing = true; else failed = true; loading = false; } });
    return () => { active = false; };
  });

  let pkg = $derived(detail?.purl ? detail.purl.replace(/^pkg:[^/]+\//, '').replace(/@.*$/, '') : null);
  let fixedList = $derived((detail?.name_key && detail.fixed?.[detail.name_key]) || []);
  let fix = $derived(nearestFix(fixedList, detail?.version));
  let cvss = $derived(detail?.scores && Object.keys(detail.scores).length ? Math.max(...Object.values(detail.scores)) : null);
  let links = $derived(detail ? advisoryLinks([detail.ref_id ?? '', ...detail.aliases]) : []);
  let editable = $derived(!!detail && canEdit(grants, detail.realm) && !!detail.ref_id && !!detail.purl && !!detail.service);
  let back = $derived('/findings' + location.search);

  async function copyFix() { if (!pkg || !fix) return; try { await navigator.clipboard.writeText(`${pkg} ${detail?.version ?? ''} -> ${fix}`.replace('  ', ' ')); copied = true; setTimeout(() => copied = false, 1500); } catch { /* clipboard blocked; the version is on screen */ } }
  async function swear(e: SubmitEvent) {
    e.preventDefault(); if (!detail) return;
    error = validateOath(kind, until, reason, allRealms, grants); if (error) return;
    busy = true;
    try {
      const result = await api<{ warning: string | null }>('/api/v1/oaths', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ advisory_id: detail.ref_id, purl: detail.purl, service: detail.service, realm: allRealms ? '' : detail.realm, all_realms: allRealms, kind, reason, until: until || null }) });
      reason = ''; until = ''; allRealms = false; error = result.warning ?? ''; revision++;
    } catch { error = 'Could not take this oath. Check the details and try again.'; } finally { busy = false; }
  }
  function go(e: MouseEvent, to: string) { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); navigate(to); }
</script>

<div class="page">
  {#if loading && !detail}<Skeleton rows={6} label="Loading finding" />
  {:else if missing}<Panel><EmptyState title="Finding not found" body="It may be in a realm you can’t see, or the link is wrong.">{#snippet action()}<Button href={back} onclick={(e) => go(e, back)}>Back to findings</Button>{/snippet}</EmptyState></Panel>
  {:else if failed}<Panel><ErrorState retry={() => revision++} /></Panel>
  {:else if detail}
    <PageHeader title={detail.summary || rowTitle(detail)}>
      {#snippet crumbs()}<a href={back} onclick={(e) => go(e, back)}>Findings</a> / <span class="mono">{detail!.ref_id ?? `#${id}`}</span>{/snippet}
      {#snippet actions()}
        {#if editable}<Button variant="primary" href="#oath">Take an oath</Button>{/if}
        {#if fix && pkg}<Button onclick={copyFix}><Icon name="copy" size={16} />{copied ? 'Copied' : 'Copy fix'}</Button>{/if}
        {#each links as link}<Button href={link.url} size="sm" variant="ghost" target="_blank" rel="noopener noreferrer">{link.id} <Icon name="external" size={14} /></Button>{/each}
      {/snippet}
    </PageHeader>
    <div class="tags"><Badge severity={detail.severity} /><Pill>{detail.kind}</Pill><Pill>{detail.status}</Pill>{#if detail.service}<Pill>{detail.service}</Pill>{/if}<Pill>{detail.realm}</Pill></div>
    <div class="stats">
      <Stat label="Exploit likelihood (EPSS)" value={detail.epss == null ? '—' : epssLabel(detail.epss, detail.epss_percentile)} tone={detail.epss != null && detail.epss >= 0.1 ? 'critical' : 'default'} />
      <Stat label="CVSS" value={cvss ?? '—'} />
      <Stat label="Fixed in" value={fix ?? '—'} tone={fix ? 'ok' : 'default'} />
      <Stat label="Services running it" value={detail.affected.length >= 25 ? '25+' : detail.affected.length} />
    </div>
    <div class="grid">
      <div class="main">
        <Panel title="Highlights" flush>
          <dl>
            <dt>Package</dt><dd class="mono">{pkg ?? '—'}</dd>
            <dt>Installed</dt><dd class="mono">{detail.version ?? '—'}</dd>
            <dt>Fixed versions</dt><dd class="mono">{fixedList.join(', ') || 'None recorded'}</dd>
            <dt>Advisory</dt><dd class="mono">{detail.ref_id ?? '—'}</dd>
            <dt>Aliases</dt><dd class="mono">{detail.aliases.join(', ') || 'None recorded'}</dd>
            <dt>CVSS by source</dt><dd>{detail.scores && Object.keys(detail.scores).length ? Object.entries(detail.scores).map(([s, v]) => `${s.toUpperCase()} ${v}`).join(' · ') : 'Not recorded'}</dd>
            <dt>Opened</dt><dd>{detail.opened_at.slice(0, 10)}</dd>
            <dt>Package URL</dt><dd class="mono">{detail.purl ?? '—'}</dd>
          </dl>
        </Panel>
        <Panel title="Where it runs" flush>
          {#if detail.affected.length}
            <ul class="list">{#each detail.affected as item}<li><strong>{item.service}</strong>{#if item.image}<span class="mono">{item.image}</span>{/if}{#if item.digest}<span class="mono dim">{item.digest}</span>{/if}</li>{/each}</ul>
          {:else}<p class="pad muted">No inventory links recorded.</p>{/if}
          {#if affectedOffset > 0 || detail.affected.length >= 25}<div class="pager"><Button size="sm" disabled={affectedOffset === 0} onclick={() => affectedOffset = Math.max(0, affectedOffset - 25)}>Previous</Button><Button size="sm" disabled={detail.affected.length < 25} onclick={() => affectedOffset += 25}>Next</Button></div>{/if}
        </Panel>
      </div>
      <aside class="rail" aria-label="Fix and decisions">
        <Panel title="Fix">
          {#if fix}<p class="fix"><span class="mono">{pkg} {detail.version}</span> → <strong class="mono">{fix}</strong></p><p class="muted small">The lowest fixed version above what you run.</p>
          {:else}<p class="muted">No fixed version recorded yet.</p>{/if}
        </Panel>
        <Panel title="Exploit likelihood">
          <EpssBar score={detail.epss} percentile={detail.epss_percentile} />
          <p class="muted small">{detail.epss == null ? 'No EPSS score for this advisory.' : 'Chance of exploitation in the next 30 days, from FIRST EPSS.'}</p>
        </Panel>
        {#if editable}
          <div id="oath"><Panel title="Take an oath">
            <form onsubmit={swear}>
              <Select label="Decision" bind:value={kind}><option value="snooze">Snooze until a date</option><option value="ignore">Ignore</option></Select>
              <Input label={`Expiry date ${kind === 'snooze' ? '(required)' : '(optional)'}`} type="date" bind:value={until} />
              <label class="field">Reason<textarea bind:value={reason} rows="3" placeholder="Why this risk is accepted"></textarea></label>
              {#if canEdit(grants, '*')}<label class="check"><input type="checkbox" bind:checked={allRealms} /> Apply to all realms</label>{/if}
              {#if error}<p class="error" role="alert">{error}</p>{/if}
              <Button type="submit" variant="primary" disabled={busy}>{busy ? 'Saving…' : 'Swear oath'}</Button>
            </form>
          </Panel></div>
        {/if}
        <Panel title="Oaths">
          {#if detail.oaths.length}<ul class="oaths">{#each detail.oaths as oath}<li><strong>{oath.kind} · {oath.status}</strong><span>{oath.reason}</span><span class="muted small">{oath.created_by} · {oath.created_at.slice(0, 10)}{oath.expires_at ? ` · until ${oath.expires_at.slice(0, 10)}` : ''}</span></li>{/each}</ul>
          {:else}<p class="muted">No oaths for this finding. It still counts and still alerts.</p>{/if}
          {#if oathsOffset > 0 || detail.oaths.length >= 25}<div class="pager"><Button size="sm" disabled={oathsOffset === 0} onclick={() => oathsOffset = Math.max(0, oathsOffset - 25)}>Previous</Button><Button size="sm" disabled={detail.oaths.length < 25} onclick={() => oathsOffset += 25}>Next</Button></div>{/if}
        </Panel>
      </aside>
    </div>
  {/if}
</div>

<style>
  .page { padding: 18px 24px 32px; display: grid; gap: var(--s4); }
  .page :global(.ph) { margin-bottom: 0; }
  .tags { display: flex; gap: var(--s2); flex-wrap: wrap; align-items: center; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: var(--s3); }
  .stats :global(.value) { font-size: 20px; }
  .grid { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: var(--s4); align-items: start; }
  .main, .rail { display: grid; gap: var(--s4); min-width: 0; }
  dl { display: grid; grid-template-columns: 160px minmax(0, 1fr); margin: 0; }
  dt, dd { padding: 9px var(--s4); border-bottom: 1px solid var(--border); margin: 0; }
  dt { color: var(--muted); font-size: var(--text-sm); }
  dd { overflow-wrap: anywhere; }
  .mono { font-family: var(--font-mono); font-size: var(--text-sm); }
  .list, .oaths { list-style: none; margin: 0; padding: 0; }
  .list li { display: grid; gap: 2px; padding: 9px var(--s4); border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
  .oaths li { display: grid; gap: 2px; padding: var(--s2) 0; border-bottom: 1px solid var(--border); }
  .dim, .muted { color: var(--muted); } .small { font-size: var(--text-sm); }
  .pad { padding: var(--s3) var(--s4); margin: 0; }
  .pager { display: flex; gap: var(--s2); justify-content: flex-end; padding: var(--s2) var(--s4); }
  .fix { font-size: var(--text-lg); margin: 0 0 4px; } .fix strong { color: var(--ok); }
  p { margin: 6px 0 0; }
  form { display: grid; gap: var(--s3); }
  .field { display: grid; gap: 6px; font-size: var(--text-sm); font-weight: 600; color: var(--muted); }
  textarea { border: 1px solid var(--border); background: var(--bg); color: var(--text); border-radius: var(--r-control); padding: 8px 11px; font-weight: 400; resize: vertical; }
  .check { display: flex; gap: var(--s2); align-items: center; font-size: var(--text-sm); }
  .error { color: var(--sev-high); font-size: var(--text-sm); margin: 0; }
  @media (max-width: 1100px) { .grid { grid-template-columns: 1fr; } }
  @media (max-width: 700px) { .page { padding: var(--s4); } dl { grid-template-columns: 1fr; } dt { border-bottom: 0; padding-bottom: 0; } }
</style>
