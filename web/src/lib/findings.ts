import type { Grant } from './api';
export type Filters = { severity:string; kind:string; service:string; has_fix:string; view_status:string; search:string; sort:string; order:string; offset:number };
export const defaultFilters: Filters = {severity:'',kind:'',service:'',has_fix:'',view_status:'open',search:'',sort:'severity',order:'desc',offset:0};
const sortFields = ['advisory', 'severity', 'epss', 'kind', 'realm', 'service', 'opened_at'];
export function sortFromSearch(search: string): {sort:string; order:string} {
  const params = new URLSearchParams(search);
  const sort = params.get('sort'); const order = params.get('order');
  return {sort: sort && sortFields.includes(sort) ? sort : 'severity', order: order === 'asc' || order === 'desc' ? order : 'desc'};
}
export function sortUrl(url: string, sort: string, order: string): string {
  const next = new URL(url); next.searchParams.set('sort', sort); next.searchParams.set('order', order);
  return next.pathname + next.search + next.hash;
}
export function findingsUrl(filters: Filters, realms: string[]): string {
  const q = new URLSearchParams({ ui: 'true', limit: '25', offset: String(filters.offset), sort: filters.sort, order: filters.order, view_status: filters.view_status });
  for (const key of ['severity', 'kind', 'service', 'has_fix', 'search'] as const) if (filters[key]) q.set(key, filters[key]);
  if (realms.length) q.set('realms', realms.join(','));
  return `/api/v1/findings?${q}`;
}
export function canEdit(grants: Grant[], realm: string): boolean { return grants.some(g => g.role === 'admin' || (g.role === 'editor' && (g.realm === '*' || g.realm === realm))); }
export function validateOath(kind: string, until: string, reason: string, allRealms: boolean, grants: Grant[]): string {
  if (!reason.trim()) return 'Give a reason for this oath.';
  if (kind === 'snooze' && !until) return 'Choose an expiry date for a snooze.';
  if (until && until <= new Date().toISOString().slice(0, 10)) return 'The expiry must be after today (UTC).';
  if (allRealms && !canEdit(grants, '*')) return 'All realms requires an editor grant on *.';
  return '';
}
export function advisoryLinks(ids: string[]): {id:string; url:string}[] {
  return [...new Set(ids)].flatMap(id => {
    if (/^CVE-\d{4}-\d{4,}$/i.test(id)) return [{id: `NVD: ${id}`, url: `https://nvd.nist.gov/vuln/detail/${id}`}, {id: `OSV: ${id}`, url: `https://osv.dev/vulnerability/${id}`}];
    if (/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i.test(id)) return [{id: `GHSA: ${id}`, url: `https://github.com/advisories/${id}`}, {id: `OSV: ${id}`, url: `https://osv.dev/vulnerability/${id}`}];
    if (/^(?:GO|OSV)-[A-Za-z0-9-]+$/.test(id)) return [{id, url: `https://osv.dev/vulnerability/${id}`}];
    return [];
  });
}
/** EPSS as a percentage with its percentile, e.g. "12.3% (top 4%)"; "—" when unscored. */
export function epssLabel(score?: number | null, percentile?: number | null): string {
  if (score == null) return '—';
  const pct = (score * 100).toFixed(score < 0.001 ? 2 : 1) + '%';
  if (percentile == null) return pct;
  const top = Math.max(1, Math.ceil((1 - percentile) * 100));
  return `${pct} (top ${top}%)`;
}

/** Saved views in the Findings sub-nav, each a preset of filters. */
export const views: {id:string; label:string; group:'Views'|'Watch'; filters:Partial<Filters>}[] = [
  {id:'feed', label:'Feed', group:'Views', filters:{}},
  {id:'likely-exploited', label:'Likely exploited', group:'Views', filters:{sort:'epss', order:'desc'}},
  {id:'fix', label:'Fix available', group:'Views', filters:{kind:'fixavailable'}},
  {id:'crit-high', label:'Critical & high', group:'Views', filters:{severity:'critical,high'}},
  {id:'k8s', label:'Kubernetes CVEs', group:'Views', filters:{kind:'k8scve'}},
  {id:'major', label:'Major releases', group:'Watch', filters:{kind:'majorrelease'}},
  {id:'notes', label:'CVEs in release notes', group:'Watch', filters:{kind:'releasenotecve'}},
  {id:'eol', label:'End of life', group:'Watch', filters:{kind:'eol'}},
];
export function viewFilters(id: string): Partial<Filters> { return {...(views.find(v => v.id === id)?.filters ?? {})}; }

type Labelled = {kind?:string; ref_id?:string|null; summary?:string|null; component_name?:string; component_version?:string; details?:Record<string, unknown>};
export function packageLabel(row: Labelled): string { return [row.component_name, row.component_version].filter(Boolean).join(' '); }
const str = (v: unknown) => typeof v === 'string' ? v : '';
/** A purl target without its scheme and type: pkg:golang/golang.org/x/crypto -> golang.org/x/crypto. */
function shortTarget(target: string): string { return target.replace(/^pkg:[^/]+\//, ''); }
/** The headline of a feed row, readable for every finding kind. */
export function rowTitle(row: Labelled): string {
  const d = row.details ?? {}; const target = shortTarget(str(d.target)); const version = str(d.version);
  switch (row.kind) {
    case 'majorrelease': return target ? `${target} ${version} is out`.replace('  ', ' ') : row.ref_id ?? 'New major release';
    case 'releasenotecve': return target ? `${target} ${version} fixes ${/^CVE-/i.test(str(d.id)) ? str(d.id) : row.ref_id ?? str(d.id)}` : row.ref_id ?? 'Release fixes a CVE';
    case 'eol': return `${target || row.ref_id || 'A component'} reaches end of life${str(d.eol) ? ` on ${str(d.eol)}` : ''}`;
    case 'oathexpired': return `Oath expired for ${row.ref_id ?? 'a finding'}`;
    default: return row.summary || row.ref_id || row.kind || 'Finding';
  }
}

/** Numeric, dot-wise version compare; a pre-release (1.0.0-rc1) sorts before its release. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => { const [core, pre] = v.replace(/^v/i, '').split(/-(.*)/s); return { parts: core!.split('.').map(n => parseInt(n, 10) || 0), pre: pre ?? '' }; };
  const x = split(a), y = split(b);
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length); i++) { const d = (x.parts[i] ?? 0) - (y.parts[i] ?? 0); if (d) return d; }
  if (x.pre === y.pre) return 0;
  return !x.pre ? 1 : !y.pre ? -1 : x.pre.localeCompare(y.pre, undefined, {numeric: true});
}
/** The lowest fixed version above the installed one (any when unknown), or null. */
export function nearestFix(fixed: string[], installed: string | null | undefined): string | null {
  const above = fixed.filter(v => !installed || compareVersions(v, installed) > 0).sort(compareVersions);
  return above[0] ?? null;
}

const urlKeys = ['severity', 'kind', 'service', 'has_fix', 'view_status', 'search'] as const;
/** Filters as they sit in the page URL, so Back from a finding restores them. */
export function filtersFromSearch(search: string): Filters {
  const q = new URLSearchParams(search); const f: Filters = { ...defaultFilters, ...sortFromSearch(search) };
  for (const k of urlKeys) { const v = q.get(k); if (v) f[k] = v; }
  if (!['open', 'snoozed', 'ignored', 'resolved'].includes(f.view_status)) f.view_status = 'open';
  const offset = Number(q.get('offset')); f.offset = Number.isInteger(offset) && offset > 0 ? offset : 0;
  return f;
}
/** The page query with these filters written in (defaults left out), other params kept. */
export function filtersSearch(f: Filters, search: string): string {
  const q = new URLSearchParams(search);
  // A key the active view presets is always written, even when cleared, so the preset does not come back on reload.
  const preset = viewFilters(q.get('view') ?? 'feed');
  for (const k of urlKeys) { if (k in preset || (f[k] && f[k] !== defaultFilters[k])) q.set(k, f[k]); else q.delete(k); }
  for (const [k, v] of [['sort', f.sort], ['order', f.order]] as const) { if (k in preset || v !== defaultFilters[k]) q.set(k, v); else q.delete(k); }
  if (f.offset) q.set('offset', String(f.offset)); else q.delete('offset');
  return q.toString() ? `?${q}` : '';
}
/** The feed's filters: the URL's, with the view's preset filling keys the URL leaves out. */
export function initialFilters(search: string): Filters {
  const f = filtersFromSearch(search); const q = new URLSearchParams(search);
  for (const [k, v] of Object.entries(viewFilters(q.get('view') ?? 'feed'))) if (!q.has(k)) (f as Record<string, unknown>)[k] = v;
  return f;
}
