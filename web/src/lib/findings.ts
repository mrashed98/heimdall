import type { Grant } from './api';
export type Filters = { severity:string; kind:string; service:string; has_fix:string; view_status:string; search:string; sort:string; order:string; offset:number };
export const defaultFilters: Filters = {severity:'',kind:'',service:'',has_fix:'',view_status:'open',search:'',sort:'severity',order:'desc',offset:0};
const sortFields = ['advisory', 'severity', 'kind', 'realm', 'service', 'opened_at'];
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
