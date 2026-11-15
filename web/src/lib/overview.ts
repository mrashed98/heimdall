export const severities = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type Severity = typeof severities[number];
export function riskScore(critical: number, high: number, medium: number): number { return critical * 10 + high * 3 + medium; }
export function statusUrl(realms: string[]): string {
  const query = new URLSearchParams();
  if (realms.length) query.set('realms', realms.join(','));
  return '/api/v1/status' + (query.size ? `?${query}` : '');
}
