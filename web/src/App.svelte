<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import Overview from './lib/Overview.svelte';
  import Findings from './lib/Findings.svelte';
  import Services from './lib/Services.svelte';
  import Releases from './lib/Releases.svelte';
  import Oaths from './lib/Oaths.svelte';
  import Access from './lib/Access.svelte';
  import NoAccess from './lib/illustrations/NoAccess.svelte';
  import NotFound from './lib/illustrations/NotFound.svelte';
  import ErrorIllustration from './lib/illustrations/ErrorState.svelte';
  import { Button, Input, Logo, Menu, NavRail, PageHeader, RealmPicker } from './lib/ui';
  import { api, onAuthState, setCsrf, setKey, type AuthState, type Identity, type Methods } from './lib/api';
  import { isAdmin } from './lib/roles';
  import { route } from './lib/nav';
  import { selectedRealms, realmUrl } from './lib/realms';

  const DOCS = 'https://mrashed98.github.io/heimdall/';
  let authState = $state<AuthState>('loading');
  let identity = $state<Identity | null>(null);
  let methods = $state<Methods | null>(null);
  let realms = $state<{ name: string }[]>([]);
  let selected = $state<string[]>([]);
  let path = $state('/');
  let username = $state(''); let password = $state(''); let key = $state('');
  let message = $state(''); let busy = $state(false);
  let theme = $state('');
  // Dev-only component catalogue at /design; the branch is dropped from production builds.
  let Catalogue = $state<Component | null>(null);

  let admin = $derived(isAdmin(identity?.grants ?? []));
  let current = $derived(route(path, admin));
  const headers: Record<string, [string, string]> = {
    overview: ['Overview', 'Risk across your realms'],
    inventory: ['Inventory', 'Services, their components and images'],
    releases: ['Releases & end of life', 'What the watchers found'],
    oaths: ['Oaths', 'Findings you chose to snooze or ignore, with the reason and who swore it'],
    settings: ['Settings', 'Members, API keys and the audit log']
  };
  let header = $derived(headers[current.page]);
  let nav = $derived([
    { href: '/findings', label: 'Findings', icon: 'findings' as const, current: current.page === 'findings' || current.page === 'finding' },
    { href: '/', label: 'Overview', icon: 'overview' as const, current: current.page === 'overview' },
    { href: '/services', label: 'Inventory', icon: 'inventory' as const, current: current.page === 'inventory' || current.page === 'service' },
    { href: '/releases', label: 'Releases', icon: 'releases' as const, current: current.page === 'releases' },
    { href: '/oaths', label: 'Oaths', icon: 'oaths' as const, current: current.page === 'oaths' },
    ...(admin ? [{ href: '/access', label: 'Settings', icon: 'settings' as const, current: current.page === 'settings', bottom: true }] : [])
  ].map(item => ({ ...item, href: item.href + realmQuery(selected) })));
  let initials = $derived((identity?.name ?? '?').split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map(s => s[0]!.toUpperCase()).join('') || '?');

  function realmQuery(list: string[]) { return list.length ? `?realms=${encodeURIComponent(list.join(','))}` : ''; }
  function syncLocation() { path = location.pathname; selected = selectedRealms(location.search); }
  function navigate(to: string) { history.pushState({}, '', to); syncLocation(); window.scrollTo(0, 0); }
  function setRealms(next: string[]) { selected = next; history.replaceState({}, '', realmUrl(location.href, next)); }
  function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light'; document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('heimdall-theme', theme); } catch { /* private mode */ }
  }
  async function loadIdentity() {
    identity = await api<Identity>('/auth/me'); setCsrf(identity.csrf_token);
    if (!identity.grants.length) { authState = 'noaccess'; return; }
    authState = 'ready';
    try { realms = await api<{ name: string }[]>('/api/v1/realms'); } catch { if (authState === 'ready') authState = 'error'; }
  }
  async function signIn(event: SubmitEvent, byKey = false) {
    event.preventDefault(); busy = true; message = '';
    try {
      if (byKey) { setKey(key); key = ''; }
      else await api<void>('/auth/local', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      password = ''; await loadIdentity();
    } catch { setKey(null); message = 'Sign-in failed. Check your credentials and try again.'; }
    finally { busy = false; }
  }
  async function signOut() { try { if (identity?.kind !== 'key') await api<void>('/auth/logout', { method: 'POST' }); } catch { /* Clear local state even when the session expired. */ } setKey(null); setCsrf(null); identity = null; authState = 'signin'; }
  onMount(() => {
    try { theme = localStorage.getItem('heimdall-theme') ?? ''; } catch { theme = ''; }
    if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
    if (import.meta.env.DEV) void import('./Catalogue.svelte').then(m => { Catalogue = m.default; });
    syncLocation(); window.addEventListener('popstate', syncLocation); onAuthState(s => { authState = s; });
    void (async () => { try { methods = await api<Methods>('/auth/login'); await loadIdentity(); } catch { if (authState === 'loading') authState = 'error'; } })();
    return () => window.removeEventListener('popstate', syncLocation);
  });
</script>

{#snippet realmPicker()}<RealmPicker realms={realms.map(r => r.name)} {selected} change={setRealms} />{/snippet}

{#if Catalogue && path === '/design'}<Catalogue />
{:else if authState === 'signin' || authState === 'loading'}
  <div class="signin">
    <a class="back" href={DOCS}>← Back to docs</a>
    <main>
      <div class="brand"><Logo size={56} /><span class="word">HEIMDALL</span><h1>Welcome back</h1><p>Sign in to keep watch over your realms.</p></div>
      <section class="card" aria-label="Sign in">
        {#if authState === 'loading'}<p class="muted" role="status">Loading…</p>
        {:else if methods}
          {#if methods.oidc}<Button href="/auth/oidc/start">Continue with {methods.oidc}</Button>{/if}
          {#if methods.oidc && methods.local}<div class="or"><span>or</span></div>{/if}
          {#if methods.local}<form onsubmit={(e) => signIn(e)}><Input label="Username" autocomplete="username" bind:value={username} required /><Input label="Password" type="password" autocomplete="current-password" bind:value={password} required />{#if message}<p class="error" role="alert">{message}</p>{/if}<Button type="submit" variant="primary" disabled={busy}>Sign in</Button></form>{/if}
          {#if !methods.local && !methods.oidc}<form onsubmit={(e) => signIn(e, true)}><Input label="API key" type="password" autocomplete="off" hint="Your key stays in this tab’s memory." bind:value={key} required />{#if message}<p class="error" role="alert">{message}</p>{/if}<Button type="submit" variant="primary" disabled={busy}>Sign in</Button></form>{/if}
          {#if message && !methods.local && methods.oidc}<p class="error" role="alert">{message}</p>{/if}
        {/if}
      </section>
      {#if methods?.local}<p class="note">Local accounts are for break-glass access. Ask an admin if you can’t sign in.</p>{/if}
    </main>
  </div>
{:else if authState === 'ready'}
  <div class="shell">
    <NavRail items={nav} home={'/findings' + realmQuery(selected)} {navigate}>
      {#snippet footer()}
        <Menu label="Account" align="start" up>
          {#snippet trigger()}<span class="avatar" title={identity?.name}>{initials}</span>{/snippet}
          <div class="account"><strong>{identity?.name}</strong><span class="muted">{[...new Set(identity?.grants.map(g => g.role))].join(', ') || 'No roles'}</span><Button size="sm" onclick={toggleTheme}>Switch to {theme === 'light' ? 'dark' : 'light'} theme</Button><Button size="sm" variant="ghost" onclick={signOut}>Sign out</Button></div>
        </Menu>
      {/snippet}
    </NavRail>
    <div class="content" class:bleed={current.page === 'findings' || current.page === 'finding'}>
      {#if current.page === 'findings' || current.page === 'finding'}<Findings realms={selected} {navigate} {realmPicker} />
      {:else if current.page === 'notfound'}<div class="state"><NotFound /><Button onclick={() => navigate('/findings')}>Go to findings</Button></div>
      {:else}
        {#if header}<PageHeader title={header[0]} description={header[1]}>{#snippet actions()}{#if current.page !== 'settings'}{@render realmPicker()}{/if}{/snippet}</PageHeader>{/if}
        {#if current.page === 'overview'}<Overview realms={selected} />
        {:else if current.page === 'inventory' || current.page === 'service'}<Services realms={selected} serviceId={current.page === 'service' ? current.id : null} />
        {:else if current.page === 'releases'}<Releases realms={selected} />
        {:else if current.page === 'oaths'}<Oaths realms={selected} grants={identity?.grants ?? []} />
        {:else if current.page === 'settings'}<Access availableRealms={realms.map(r => r.name)} />{/if}
      {/if}
    </div>
  </div>
{:else}
  <main class="state">{#if authState === 'noaccess'}<NoAccess /><Button onclick={signOut}>Sign out</Button>{:else}<ErrorIllustration /><Button onclick={() => location.reload()}>Try again</Button>{/if}</main>
{/if}

<style>
  .signin { min-height: 100vh; display: flex; flex-direction: column; padding: 20px 24px; background: radial-gradient(700px 420px at 50% 38%, var(--glow-steel) 0%, transparent 70%), var(--bg); }
  .back { color: var(--muted); font-size: var(--text-sm); align-self: flex-start; }
  .signin main { flex: 1; display: grid; place-items: center; align-content: center; gap: var(--s4); }
  .brand { display: grid; justify-items: center; gap: 10px; text-align: center; }
  .word { font-family: var(--font-display); font-weight: 700; letter-spacing: .14em; color: var(--gold); font-size: 20px; }
  .brand h1 { font-size: 24px; margin: 6px 0 0; } .brand p { color: var(--muted); margin: 0; }
  .card { width: min(380px, 100%); background: var(--panel); border: 1px solid var(--border); border-radius: var(--r-card); padding: var(--s5); box-shadow: 0 24px 70px var(--shadow); position: relative; overflow: hidden; display: grid; gap: var(--s3); }
  .card::before { content: ''; position: absolute; inset: 0 0 auto 0; height: 2px; background: var(--bifrost); }
  .card form { display: grid; gap: var(--s3); }
  .or { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 12px; } .or::before, .or::after { content: ''; flex: 1; height: 1px; background: var(--border); }
  .error { color: var(--sev-high); margin: 0; font-size: var(--text-sm); }
  .note { color: var(--muted); font-size: 12px; text-align: center; margin: 0; max-width: 380px; }
  .muted { color: var(--muted); }
  .shell { display: flex; min-height: 100vh; }
  .content { flex: 1; min-width: 0; padding: 18px 24px 32px; }
  .content.bleed { padding: 0; }
  .avatar { width: 34px; height: 34px; border-radius: 50%; border: 1px solid var(--gold); background: var(--gold-soft); color: var(--gold); display: grid; place-items: center; font-weight: 700; font-size: 11px; }
  .account { display: grid; gap: var(--s2); } .account span { font-size: var(--text-sm); }
  .state { max-width: 560px; margin: 12vh auto; padding: var(--s5); display: grid; gap: var(--s4); justify-items: start; }
  @media (max-width: 700px) { .shell { flex-direction: column; } .content { padding: var(--s4); } }
</style>
