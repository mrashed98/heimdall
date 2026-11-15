import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, onAuthState, setCsrf, setKey } from './api';
afterEach(() => { vi.unstubAllGlobals(); setCsrf(null); setKey(null); onAuthState(() => {}); });
describe('API', () => {
  it('sends CSRF only for mutations', async () => {
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(new Response('{}'))); vi.stubGlobal('fetch', fetcher); setCsrf('secret');
    await api('/test'); await api('/test', { method: 'POST' });
    expect(fetcher.mock.calls[0][1].headers.get('X-CSRF-Token')).toBeNull();
    expect(fetcher.mock.calls[1][1].headers.get('X-CSRF-Token')).toBe('secret');
    expect(fetcher.mock.calls[1][1].credentials).toBe('same-origin');
  });
  it.each([[401, 'unauthorized', 'signin'], [403, 'no_access', 'noaccess']] as const)('maps %s to %s', async (status, error, state) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error }), { status })));
    const listener = vi.fn(); onAuthState(listener); await expect(api('/test')).rejects.toThrow(); expect(listener).toHaveBeenCalledWith(state);
  });
});
