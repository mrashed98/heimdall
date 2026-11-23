import { describe, expect, it } from 'vitest';
import { route } from './nav';

describe('route', () => {
  it('maps every page', () => {
    expect(route('/', false)).toEqual({ page: 'overview' });
    expect(route('/findings', false)).toEqual({ page: 'findings' });
    expect(route('/findings/42', false)).toEqual({ page: 'finding', id: 42 });
    expect(route('/services', false)).toEqual({ page: 'inventory' });
    expect(route('/services/7', false)).toEqual({ page: 'service', id: 7 });
    expect(route('/releases', false)).toEqual({ page: 'releases' });
    expect(route('/oaths', false)).toEqual({ page: 'oaths' });
    expect(route('/access', true)).toEqual({ page: 'settings' });
  });
  it('rejects bad ids and unknown paths', () => {
    for (const path of ['/findings/0', '/findings/abc', '/findings/01', '/services/-1', '/nope', '/findings/1/x', '/findings/9007199254740993']) expect(route(path, true)).toEqual({ page: 'notfound' });
  });
  it('hides settings from non-admins', () => {
    expect(route('/access', false)).toEqual({ page: 'notfound' });
  });
});
