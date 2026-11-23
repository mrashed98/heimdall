export type Route =
  | { page: 'overview' | 'findings' | 'inventory' | 'releases' | 'oaths' | 'settings' | 'notfound' }
  | { page: 'finding' | 'service'; id: number };

const fixed: Record<string, Route['page']> = { '/': 'overview', '/findings': 'findings', '/services': 'inventory', '/releases': 'releases', '/oaths': 'oaths' };

/** The page for a URL path. Settings (/access) is admin-only. */
export function route(path: string, admin: boolean): Route {
  if (path === '/access') return { page: admin ? 'settings' : 'notfound' };
  const page = fixed[path];
  if (page) return { page } as Route;
  const m = /^\/(findings|services)\/([1-9]\d*)$/.exec(path);
  if (m && Number.isSafeInteger(Number(m[2]))) return { page: m[1] === 'findings' ? 'finding' : 'service', id: Number(m[2]) };
  return { page: 'notfound' };
}
