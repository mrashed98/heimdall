import { PAGE_SIZE } from './data-pages';
export function accessUrl(section: string, offset: number, sort: string, order: string, filters: Record<string,string> = {}): string {
  const q = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset), sort, order });
  for (const [key, value] of Object.entries(filters)) if (value) q.set(key, value);
  return `/api/v1/${section}?${q}`;
}
export function auditFilters(actor: string, action: string, since: string, until: string): Record<string,string> {
  return { actor: actor.trim(), action: action.trim(), since: since ? `${since}T00:00:00Z` : '', until: until ? `${until}T23:59:59.999999Z` : '' };
}
