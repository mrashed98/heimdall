<script lang="ts">
  import { onMount } from 'svelte';
  import Overview from './lib/Overview.svelte';
  import Findings from './lib/Findings.svelte';
  import logo from './lib/assets/logo.svg';
  import SignInHero from './lib/illustrations/SignInHero.svelte';
  import NoAccess from './lib/illustrations/NoAccess.svelte';
  import NotFound from './lib/illustrations/NotFound.svelte';
  import ErrorState from './lib/illustrations/ErrorState.svelte';
  import { api, onAuthState, setCsrf, setKey, type AuthState, type Identity, type Methods } from './lib/api';
  import { isAdmin } from './lib/roles';
  import { selectedRealms, realmUrl } from './lib/realms';
  let authState = $state<AuthState>('loading');
  let identity = $state<Identity | null>(null);
  let methods = $state<Methods | null>(null);
  let realms = $state<{name: string}[]>([]);
  let selected = $state<string[]>([]);
  let path = $state('/');
  let username = $state(''); let password = $state(''); let key = $state('');
  let message = $state(''); let busy = $state(false); let menu = $state(false);
  let theme = $state('');
  const pages = [
    { path: '/', label: 'Overview', description: 'Overview: risk across your realms' },
    { path: '/findings', label: 'Findings', description: 'Findings: vulnerabilities and other risks' },
    { path: '/services', label: 'Services', description: 'Services: inventory and dependencies' },
    { path: '/releases', label: 'Releases', description: 'Releases: updates and end-of-life notices' },
    { path: '/oaths', label: 'Oaths', description: 'Oaths: snoozed or ignored findings' },
    { path: '/access', label: 'Access', description: 'Access: users, API keys and audit' }
  ];
  let admin = $derived(isAdmin(identity?.grants ?? []));
  let page = $derived(pages.find(p => p.path === path && (p.path !== '/access' || admin)));
  function syncLocation() { path = location.pathname; selected = selectedRealms(location.search); }
  function navigate(to: string) { history.pushState({}, '', to + location.search); syncLocation(); menu = false; }
  function selectRealm(name: string, checked: boolean) { selected = checked ? [...selected, name] : selected.filter(r => r !== name); history.replaceState({}, '', realmUrl(location.href, selected)); }
  function toggleTheme() { const dark = document.documentElement.dataset.theme ? theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; theme = dark ? 'light' : 'dark'; document.documentElement.dataset.theme = theme; localStorage.setItem('heimdall-theme', theme); }
  async function loadIdentity() {
    identity = await api<Identity>('/auth/me'); setCsrf(identity.csrf_token);
    if (!identity.grants.length) { authState = 'noaccess'; return; }
    authState = 'ready';
    try { realms = await api<{name: string}[]>('/api/v1/realms'); } catch { if (authState === 'ready') authState = 'error'; }
  }
  async function signIn(event: SubmitEvent, byKey = false) {
    event.preventDefault(); busy = true; message = '';
    try {
      if (byKey) { setKey(key); key = ''; }
      else await api<void>('/auth/local', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      password = ''; await loadIdentity();
    } catch { setKey(null); message = 'Sign-in failed. Please check your credentials and try again.'; }
    finally { busy = false; }
  }
  async function signOut() { try { if (identity?.kind !== 'key') await api<void>('/auth/logout', { method: 'POST' }); } catch { /* Clear local authState even when the session expired. */ } setKey(null); setCsrf(null); identity = null; authState = 'signin'; }
  onMount(() => {
    theme = localStorage.getItem('heimdall-theme') ?? ''; if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
    syncLocation(); window.addEventListener('popstate', syncLocation); onAuthState(s => { authState = s; });
    void (async () => { try { methods = await api<Methods>('/auth/login'); await loadIdentity(); } catch { if (authState === 'loading') authState = 'error'; } })();
    return () => window.removeEventListener('popstate', syncLocation);
  });
</script>

{#if authState === 'signin' || authState === 'loading'}
  <header class="signin-header"><img src={logo} alt="" /><strong>Heimdall</strong></header>
  <main class="signin">
    <section class="intro"><p class="eyebrow">HEIMDALL / ACCESS</p><h1>The watcher at the Bifröst</h1><p>Keep watch over the services and dependencies in your realms.</p><SignInHero /></section>
    <section class="login"><p class="eyebrow">WELCOME</p><h2>Sign in</h2><p>Continue to your realms.</p>
      {#if authState === 'loading'}<p>Loading…</p>{:else if methods}
        {#if methods.oidc}<a class="primary button oidc" href="/auth/oidc/start">Sign in with {methods.oidc}</a>{/if}
        {#if methods.local}<form onsubmit={(e) => signIn(e)}><label>Username<input autocomplete="username" bind:value={username} required /></label><label>Password<input type="password" autocomplete="current-password" bind:value={password} required /></label><button class="primary" disabled={busy}>Sign in</button></form>{/if}
        {#if !methods.local && !methods.oidc}<form onsubmit={(e) => signIn(e, true)}><label>API key<input type="password" autocomplete="off" bind:value={key} required /></label><p class="hint">Your key stays in this tab's memory.</p><button class="primary" disabled={busy}>Sign in</button></form>{/if}
        {#if message}<p role="alert">{message}</p>{/if}
      {/if}
    </section>
  </main>
{:else}
  <header class="topbar"><a class="brand" href="/" onclick={(e) => { e.preventDefault(); navigate('/'); }}><img src={logo} alt="" /><strong>Heimdall</strong></a>
    <div class="top-actions">
      {#if authState === 'ready'}<details class="dropdown"><summary>Realms <span class="count">{selected.length || 'All'}</span></summary><div class="popover"><strong>Filter realms</strong><label><input type="checkbox" checked={selected.length === 0} onchange={() => { selected = []; history.replaceState({}, '', realmUrl(location.href, [])); }} /> All my realms</label>{#each realms as realm}<label><input type="checkbox" checked={selected.includes(realm.name)} onchange={(e) => selectRealm(realm.name, e.currentTarget.checked)} /> {realm.name}</label>{/each}</div></details>{/if}
      <button onclick={toggleTheme} aria-label="Toggle light and dark theme" title="Toggle theme">◐</button>
      {#if identity}<details class="dropdown"><summary>{identity.name}</summary><div class="popover"><strong>{identity.name}</strong><p>{[...new Set(identity.grants.map(g => g.role))].join(', ') || 'No roles'}</p><button onclick={signOut}>Sign out</button></div></details>{/if}
    </div>
  </header>
  {#if authState === 'ready'}<div class="layout"><nav aria-label="Main navigation"><button class="mobile-menu" onclick={() => menu = !menu} aria-expanded={menu}>Menu ☰</button><div class:open={menu} class="navlinks">{#each pages.filter(p => p.path !== '/access' || admin) as item}<a href={item.path + location.search} title={item.description} aria-current={path === item.path ? 'page' : undefined} onclick={(e) => { e.preventDefault(); navigate(item.path); }}>{item.label}</a>{/each}</div></nav><main class="content">{#if page}<p class="eyebrow">YOUR REALMS / {page.label.toUpperCase()}</p><h1>{page.label}</h1><p class="description">{page.description.split(': ')[1]}</p>{#if path === '/'}<Overview realms={selected} />{:else if path === '/findings'}<Findings realms={selected} grants={identity?.grants ?? []} />{:else}<div class="placeholder"><span class="marker"></span><p>Coming in the next step</p></div>{/if}{:else}<NotFound /><a href="/" onclick={(e) => { e.preventDefault(); navigate('/'); }}>Return to overview</a>{/if}</main></div>
  {:else}<main class="authState-page">{#if authState === 'noaccess'}<NoAccess /><button onclick={signOut}>Sign out</button>{:else}<ErrorState /><button onclick={() => location.reload()}>Try again</button>{/if}</main>{/if}
{/if}
<style>
  .signin-header,.topbar { display:flex; align-items:center; gap:.65rem; padding: .8rem clamp(1rem,3vw,2.5rem); border-bottom:1px solid var(--border); } .signin-header img,.brand img { width:36px; height:36px; } .signin-header strong,.brand strong { font-size:1.15rem; letter-spacing:-.03em; } .signin-header,.topbar { position:relative; } .signin-header:after,.topbar:after { content:''; position:absolute; height:3px; bottom:-2px; left:0; right:0; background:var(--bifrost); opacity:.85; }
  .signin { max-width:1100px; margin:0 auto; min-height:calc(100vh - 65px); display:grid; grid-template-columns:1.2fr 1fr; align-items:center; gap:clamp(3rem,9vw,9rem); padding:3rem 2rem; } h1 { font-size:clamp(2rem,4vw,3.4rem); letter-spacing:-.045em; line-height:1.08; margin:.5rem 0 1rem; } h2 { font-size:1.8rem; margin:.5rem 0; } p { line-height:1.55; } .intro > p:not(.eyebrow), .description, .login > p:not(.eyebrow) { color:var(--muted); } .intro :global(figure) { margin-top:2.5rem; } .eyebrow { color:var(--accent-high); font-size:.72rem; font-weight:700; letter-spacing:.13em; } .login { border:1px solid var(--border); border-radius:10px; padding:2rem; background:var(--surface); } form { display:grid; gap:1rem; margin-top:1.5rem; } form label { display:grid; gap:.4rem; font-weight:600; font-size:.9rem; } .hint { color:var(--muted); font-size:.85rem; margin:0; } .primary { background:var(--accent-high); color:var(--page); border-color:var(--accent-high); font-weight:700; } .oidc { display:block; text-align:center; text-decoration:none; margin-top:1.5rem; }
  .topbar { justify-content:space-between; } .brand { display:flex; align-items:center; gap:.65rem; text-decoration:none; color:var(--text); } .top-actions { display:flex; align-items:center; gap:.7rem; } .dropdown { position:relative; } summary { list-style:none; padding:.6rem; } summary::-webkit-details-marker { display:none; } .count { color:var(--accent-high); } .popover { position:absolute; right:0; z-index:3; min-width:200px; max-height:50vh; overflow:auto; background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:1rem; box-shadow:0 8px 24px var(--border); } .popover label { display:block; margin-top:.8rem; white-space:nowrap; } .popover p { color:var(--muted); } .layout { display:grid; grid-template-columns:220px 1fr; min-height:calc(100vh - 65px); } nav { border-right:1px solid var(--border); padding:2rem 1rem; } .navlinks { display:grid; gap:.25rem; } .navlinks a { color:var(--muted); text-decoration:none; border-radius:6px; padding:.75rem 1rem; } .navlinks a[aria-current=page] { color:var(--accent-high); background:var(--accent-low); font-weight:700; } .content { padding:clamp(2rem,5vw,5rem); } .content h1 { font-size:clamp(2rem,3vw,2.8rem); } .placeholder { margin-top:4rem; border-top:1px solid var(--border); padding-top:1.5rem; color:var(--muted); display:flex; gap:1rem; align-items:center; } .marker { width:8px; height:8px; border-radius:50%; background:var(--accent); } .mobile-menu { display:none; } .authState-page { max-width:650px; margin:7rem auto; padding:2rem; } .authState-page button { margin-top:2rem; }
  @media(max-width:700px) { .signin { grid-template-columns:1fr; gap:2rem; padding:3rem 1.25rem; } .intro :global(figure) { margin-top:1rem; } .intro :global(svg) { width:160px; } .layout { display:block; } nav { border-right:0; border-bottom:1px solid var(--border); padding:.75rem 1rem; } .mobile-menu { display:block; } .navlinks { display:none; padding-top:.5rem; } .navlinks.open { display:grid; } .topbar { padding:.7rem 1rem; } .top-actions { gap:.1rem; } }
</style>
