import { describe, it, expect } from 'vitest';
import { epssLabel, findingsUrl, validateOath, canEdit, advisoryLinks, defaultFilters, sortFromSearch, sortUrl, type Filters } from './findings';
const filters: Filters = {severity:'high',kind:'vuln',service:'api team',has_fix:'true',view_status:'snoozed',search:'CVE + pkg',sort:'severity',order:'asc',offset:25};
describe('findings', () => {
 it('defaults to severity descending and carries sort in the URL', () => {
  const sort=sortFromSearch(''); expect(sort).toEqual({sort:'severity',order:'desc'});
  const page=sortUrl('https://example.test/findings?realms=prod',sort.sort,sort.order);
  expect(sortFromSearch(new URL(page,'https://example.test').search)).toEqual(sort);
  const q=new URL(findingsUrl({...defaultFilters,...sort},[]),'https://example.test').searchParams;
  expect(q.get('sort')).toBe('severity'); expect(q.get('order')).toBe('desc'); expect(q.get('ui')).toBe('true');
  expect(sortFromSearch('?sort=kind&order=asc')).toEqual({sort:'kind',order:'asc'});
  expect(sortFromSearch('?sort=epss&order=desc')).toEqual({sort:'epss',order:'desc'});
 });
 it('builds a paged and encoded server query', () => { const q=new URL(findingsUrl(filters,['prod','dev']), 'http://localhost').searchParams; expect(q.get('realms')).toBe('prod,dev'); expect(q.get('search')).toBe('CVE + pkg'); expect(q.get('service')).toBe('api team'); expect(q.get('offset')).toBe('25'); expect(q.get('view_status')).toBe('snoozed'); });
 it('validates snoozes, dates, reason and all-realms authority', () => {const grants=[{role:'editor',realm:'prod'}]; expect(validateOath('snooze','','later',false,grants)).toMatch(/expiry/); expect(validateOath('ignore','',' ',false,grants)).toMatch(/reason/); expect(validateOath('ignore','','later',true,grants)).toMatch(/editor/); expect(validateOath('snooze','2000-01-01','later',false,grants)).toMatch(/after today/); expect(validateOath('snooze','2999-01-01','later',true,[{role:'editor',realm:'*'}])).toBe(''); expect(canEdit(grants,'dev')).toBe(false); });
 it('builds links only for recognized identifiers', () => {expect(advisoryLinks(['CVE-2026-1234','GHSA-2345-6789-cfgh','GO-2026-1','javascript:bad']).map(x=>x.id)).toEqual(['NVD: CVE-2026-1234','OSV: CVE-2026-1234','GHSA: GHSA-2345-6789-cfgh','OSV: GHSA-2345-6789-cfgh','GO-2026-1']);});
 it('formats EPSS as a percentage and percentile', () => {expect(epssLabel(0.04753,0.92097)).toBe('4.8% (top 8%)'); expect(epssLabel(0.97,0.9999)).toBe('97.0% (top 1%)'); expect(epssLabel(0.0004,0.05)).toBe('0.04% (top 95%)'); expect(epssLabel(0.2)).toBe('20.0%'); expect(epssLabel(undefined)).toBe('—'); expect(epssLabel(null,0.5)).toBe('—');});
});
import { views, viewFilters, packageLabel, rowTitle } from './findings';
describe('feed views', () => {
 it('maps each view to filters', () => {
  expect(viewFilters('likely-exploited')).toEqual({sort:'epss',order:'desc'});
  expect(viewFilters('crit-high')).toEqual({severity:'critical,high'});
  expect(viewFilters('fix')).toEqual({kind:'fixavailable'});
  expect(viewFilters('feed')).toEqual({});
  expect(viewFilters('nope')).toEqual({});
  expect(new Set(views.map(v=>v.id)).size).toBe(views.length);
 });
 it('labels the package line', () => {
  expect(packageLabel({component_name:'log4j-core',component_version:'2.14.1'})).toBe('log4j-core 2.14.1');
  expect(packageLabel({component_name:'log4j-core'})).toBe('log4j-core');
  expect(packageLabel({})).toBe('');
 });
 it('titles rows of every kind', () => {
  expect(rowTitle({kind:'vuln',ref_id:'GHSA-x',summary:'RCE in Log4j',details:{}})).toBe('RCE in Log4j');
  expect(rowTitle({kind:'vuln',ref_id:'GHSA-x',details:{}})).toBe('GHSA-x');
  expect(rowTitle({kind:'majorrelease',ref_id:'v0.59.0',details:{target:'pkg:golang/golang.org/x/crypto',version:'v0.59.0'}})).toBe('golang.org/x/crypto v0.59.0 is out');
  expect(rowTitle({kind:'releasenotecve',ref_id:'GHSA-h',details:{target:'pkg:golang/github.com/gin-gonic/gin',version:'v1.7.7',id:'CVE-2020-28483'}})).toBe('github.com/gin-gonic/gin v1.7.7 fixes CVE-2020-28483');
  expect(rowTitle({kind:'eol',ref_id:null,details:{target:'postgres 13',eol:'2025-11-13'}})).toBe('postgres 13 reaches end of life on 2025-11-13');
  expect(rowTitle({kind:'oathexpired',ref_id:'GHSA-y',details:{}})).toBe('Oath expired for GHSA-y');
  expect(rowTitle({kind:'weird',ref_id:null,details:{}})).toBe('weird');
 });
});
import { nearestFix, compareVersions } from './findings';
describe('fix versions', () => {
 it('compares dotted versions numerically', () => {
  expect(compareVersions('2.9.10.8','2.9.8')).toBeGreaterThan(0);
  expect(compareVersions('v1.7.7','1.7.7')).toBe(0);
  expect(compareVersions('4.2.26','4.2.3')).toBeGreaterThan(0);
  expect(compareVersions('1.0.0-rc1','1.0.0')).toBeLessThan(0);
 });
 it('picks the lowest fixed version above the installed one', () => {
  expect(nearestFix(['2.6.7.4','2.12.1','2.9.10.8'],'2.9.8')).toBe('2.9.10.8');
  expect(nearestFix(['2.15.0'],'2.14.1')).toBe('2.15.0');
  expect(nearestFix(['1.0.0'],'2.0.0')).toBeNull();
  expect(nearestFix([],'1.0.0')).toBeNull();
  expect(nearestFix(['3.1','2.5'],null)).toBe('2.5');
 });
});
import { filtersFromSearch, filtersSearch } from './findings';
describe('filters in the URL', () => {
 it('round-trips every filter and the page, omitting defaults', () => {
  const f: Filters = {severity:'critical,high',kind:'vuln',service:'api team',has_fix:'true',view_status:'snoozed',search:'log4j',sort:'epss',order:'desc',offset:50};
  const search = filtersSearch(f, '?realms=prod&view=fix');
  const q = new URLSearchParams(search);
  expect(q.get('realms')).toBe('prod'); expect(q.get('view')).toBe('fix');
  expect(filtersFromSearch(search)).toEqual(f);
  expect(filtersSearch(defaultFilters, '?realms=prod')).toBe('?realms=prod');
  expect(filtersFromSearch('')).toEqual(defaultFilters);
 });
 it('ignores junk values', () => {
  expect(filtersFromSearch('?offset=-5&view_status=evil&order=up').offset).toBe(0);
  expect(filtersFromSearch('?view_status=evil').view_status).toBe('open');
 });
});
import { initialFilters } from './findings';
describe('review fixes', () => {
 it('keeps a cleared view preset cleared on reload', () => {
  expect(initialFilters('?view=fix').kind).toBe('fixavailable');
  expect(initialFilters(filtersSearch({...defaultFilters}, '?view=fix')).kind).toBe('');
  expect(initialFilters(filtersSearch({...defaultFilters}, '?view=likely-exploited')).sort).toBe('severity');
 });
 it('writes the query without URLSearchParams.size', () => {
  const d = Object.getOwnPropertyDescriptor(URLSearchParams.prototype, 'size');
  Object.defineProperty(URLSearchParams.prototype, 'size', {get: () => undefined, configurable: true});
  try { expect(filtersSearch({...defaultFilters, kind:'eol'}, '?realms=prod')).toBe('?realms=prod&kind=eol'); }
  finally { if (d) Object.defineProperty(URLSearchParams.prototype, 'size', d); }
 });
 it('compares numeric pre-releases numerically', () => {
  expect(compareVersions('1.0.0-rc10', '1.0.0-rc2')).toBeGreaterThan(0);
  expect(nearestFix(['1.0.0-rc10','1.0.0-rc2'],'0.9')).toBe('1.0.0-rc2');
 });
 it('maps the watch views', () => {
  expect(viewFilters('k8s')).toEqual({kind:'k8scve'});
  expect(viewFilters('major')).toEqual({kind:'majorrelease'});
  expect(viewFilters('notes')).toEqual({kind:'releasenotecve'});
  expect(viewFilters('eol')).toEqual({kind:'eol'});
 });
});
