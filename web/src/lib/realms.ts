export function selectedRealms(search: string): string[] {
  return new URLSearchParams(search).get('realms')?.split(',').filter(Boolean) ?? [];
}
export function realmUrl(url: string, realms: string[]): string {
  const next = new URL(url);
  if (realms.length) next.searchParams.set('realms', realms.join(','));
  else next.searchParams.delete('realms');
  return next.pathname + next.search + next.hash;
}
