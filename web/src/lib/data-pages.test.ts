import { describe, expect, it } from 'vitest';
import { componentUrl, dataUrl, nextSort, expiryError } from './data-pages';
describe('data page queries', () => {
 it('encodes paging, realms, sorting and filters', () => {
  const url = new URL(dataUrl('/api/v1/ui/releases',['prod','dev'],25,'date','desc',{kind:'eol'}),'http://localhost');
  expect(url.searchParams.toString()).toBe('limit=25&offset=25&sort=date&order=desc&realms=prod%2Cdev&kind=eol');
 });
 it('toggles sorting and rejects missing or past oath dates', () => {
  expect(nextSort('name','asc','name')).toEqual(['name','desc']);
  expect(nextSort('name','desc','realm')).toEqual(['realm','asc']);
  expect(expiryError('')).toBeTruthy(); expect(expiryError('2000-01-01')).toBeTruthy(); expect(expiryError('2999-01-01')).toBe('');
 });
 it('searches components with an optional upper version bound', () => {
  expect(componentUrl(' log4j ','',[],0)).toBe('/api/v1/components?search=log4j&limit=25&offset=0');
  expect(componentUrl('log4j','2.17 ',['prod'],25)).toBe('/api/v1/components?search=log4j&limit=25&offset=25&version_lt=2.17&realms=prod');
 });
});
