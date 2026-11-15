export interface Grant { role: string; realm: string }
export interface Identity { kind: string; name: string; grants: Grant[]; csrf_token: string | null }
export interface Methods { local: boolean; oidc: string | null }
export type AuthState = 'loading' | 'signin' | 'ready' | 'noaccess' | 'error';
let token: string | null = null;
let csrf: string | null = null;
let listener: (state: AuthState) => void = () => {};
export function onAuthState(fn: (state: AuthState) => void) { listener = fn; }
export function setKey(key: string | null) { token = key; }
export function setCsrf(value: string | null) { csrf = value; }
export class ApiError extends Error { constructor(public status: number, public code: string) { super(`Request failed (${status})`); } }
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrf) headers.set('X-CSRF-Token', csrf);
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (!response.ok) {
    if (response.status === 401) listener('signin');
    else if (response.status === 403) {
      const body = await response.clone().json().catch(() => null);
      if (body?.error === 'no_access') listener('noaccess');
    }
    const body = await response.json().catch(() => null);
    throw new ApiError(response.status, typeof body?.error === 'string' ? body.error : '');
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
