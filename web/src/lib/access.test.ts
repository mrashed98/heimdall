import { describe, expect, it } from 'vitest';
import { accessUrl, auditFilters } from './access';
describe('access lists', () => {
  it('encodes paging, sorting and audit filters', () => {
    const url = new URL(accessUrl('audit', 25, 'actor', 'desc', auditFilters(' alice ', 'login success', '2026-11-01', '2026-11-15')), 'http://localhost');
    for (const [key, value] of Object.entries({limit:'25', offset:'25', sort:'actor', order:'desc', actor:'alice', action:'login success', since:'2026-11-01T00:00:00Z', until:'2026-11-15T23:59:59.999999Z'})) expect(url.searchParams.get(key)).toBe(value);
  });
  it('omits empty filters', () => expect(accessUrl('audit',0,'date','desc',auditFilters('','','',''))).not.toContain('actor='));
});
