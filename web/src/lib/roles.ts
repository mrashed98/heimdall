import type { Grant } from './api';
export function isAdmin(grants: Grant[]): boolean {
  return grants.some(grant => grant.role === 'admin');
}
