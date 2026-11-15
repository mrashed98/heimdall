import { describe, it, expect } from 'vitest';
import { findingsUrl, validateOath, canEdit, advisoryLinks, type Filters } from './findings';
const filters: Filters = {severity:'high',kind:'vuln',service:'api team',has_fix:'true',view_status:'snoozed',search:'CVE + pkg',sort:'severity',order:'asc',offset:25};
describe('findings', () => {
 it('builds a paged and encoded server query', () => { const q=new URL(findingsUrl(filters,['prod','dev']), 'http://localhost').searchParams; expect(q.get('realms')).toBe('prod,dev'); expect(q.get('search')).toBe('CVE + pkg'); expect(q.get('service')).toBe('api team'); expect(q.get('offset')).toBe('25'); expect(q.get('view_status')).toBe('snoozed'); });
 it('validates snoozes, dates, reason and all-realms authority', () => {const grants=[{role:'editor',realm:'prod'}]; expect(validateOath('snooze','','later',false,grants)).toMatch(/expiry/); expect(validateOath('ignore','',' ',false,grants)).toMatch(/reason/); expect(validateOath('ignore','','later',true,grants)).toMatch(/editor/); expect(validateOath('snooze','2000-01-01','later',false,grants)).toMatch(/after today/); expect(validateOath('snooze','2999-01-01','later',true,[{role:'editor',realm:'*'}])).toBe(''); expect(canEdit(grants,'dev')).toBe(false); });
 it('builds links only for recognized identifiers', () => {expect(advisoryLinks(['CVE-2026-1234','GHSA-2345-6789-cfgh','GO-2026-1','javascript:bad']).map(x=>x.id)).toEqual(['NVD: CVE-2026-1234','OSV: CVE-2026-1234','GHSA: GHSA-2345-6789-cfgh','OSV: GHSA-2345-6789-cfgh','GO-2026-1']);});
});
