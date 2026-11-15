<script lang="ts">
 import { api, ApiError, type Grant } from './api';
 import { accessUrl, auditFilters } from './access';
 import { nextSort } from './data-pages';
 import Table from './components/Table.svelte'; import Pagination from './components/Pagination.svelte'; import Skeleton from './components/Skeleton.svelte'; import RetryState from './components/RetryState.svelte'; import EmptyState from './components/EmptyState.svelte';
 let {availableRealms}:{availableRealms:string[]}=$props();
 type User={id:number,kind:string,name:string,email:string|null,last_login_at:string|null,disabled:boolean,grants:Grant[]};
 type Key={name:string,scope:string,created_at:string};
 type Audit={id:number,occurred_at:string,actor:string|null,action:string,method:string|null,ip:string|null,detail:unknown};
 let tab=$state<'users'|'keys'|'audit'>('users'), rows=$state<(User|Key|Audit)[]>([]), offset=$state(0), sort=$state('name'), order=$state('asc'), loading=$state(true), failed=$state(false), revision=$state(0);
 let actor=$state(''), actionFilter=$state(''), since=$state(''), until=$state('');
 let target=$state<User|null>(null), draft=$state<Grant[]>([]), error=$state(''), busy=$state(false), keyName=$state(''), scope=$state('read'), createdKey=$state(''), copied=$state(false), revoke=$state<Key|null>(null);
 let url=$derived(accessUrl(tab,offset,sort,order,tab==='audit'?auditFilters(actor,actionFilter,since,until):{}));
 $effect(()=>{const path=url;revision;let active=true;loading=true;failed=false;api<(User|Key|Audit)[]>(path).then(data=>{if(active){rows=data;loading=false;}}).catch(()=>{if(active){failed=true;loading=false;}});return ()=>{active=false;};});
 function switchTab(value:'users'|'keys'|'audit'){tab=value;offset=0;sort=value==='audit'?'date':'name';order=value==='audit'?'desc':'asc';target=null;revoke=null;error='';createdKey='';}
 function changeSort(field:string){[sort,order]=nextSort(sort,order,field);offset=0;}
 function sortState(field:string):'ascending'|'descending'|'none'{return sort===field?(order==='asc'?'ascending':'descending'):'none';}
 function edit(user:User){target=user;draft=user.grants.map(g=>({...g}));error='';}
 function toggle(role:string,realm:string,checked:boolean){draft=checked?[...draft,{role,realm}]:draft.filter(g=>g.role!==role||g.realm!==realm);}
 async function saveGrants(){if(!target)return;busy=true;error='';try{await api(`/api/v1/users/${target.id}/grants`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(draft)});target=null;revision++;}catch(e){error=e instanceof ApiError && e.code==='admin_not_allowed'?'Admin access requires this user to be listed in the server’s admins configuration.':'Could not save grants. Please try again.';}finally{busy=false;}}
 async function setDisabled(user:User){busy=true;error='';try{await api(`/api/v1/users/${user.id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({disabled:!user.disabled})});revision++;}catch{error='Could not update this user. Please try again.';}finally{busy=false;}}
 async function createKey(event:SubmitEvent){event.preventDefault();busy=true;error='';createdKey='';try{const result=await api<{key:string}>('/api/v1/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:keyName,scope})});createdKey=result.key;keyName='';copied=false;revision++;}catch(e){error=e instanceof ApiError && e.code?e.code:'Could not create this key. Please try again.';}finally{busy=false;}}
 async function revokeKey(){if(!revoke)return;busy=true;error='';try{await api(`/api/v1/keys/${encodeURIComponent(revoke.name)}`,{method:'DELETE'});revoke=null;revision++;}catch{error='Could not revoke this key. Please try again.';}finally{busy=false;}}
 async function copyKey(){try{await navigator.clipboard.writeText(createdKey);copied=true;}catch{error='Could not copy. Select and copy the key above.';}}
 function date(value:string|null){return value?new Date(value).toLocaleString():'Never';}
</script>
<div class="page">
 <div class="tabs" aria-label="Access sections">{#each [['users','Users'],['keys','API keys'],['audit','Audit log']] as [id,label]}<button aria-pressed={tab===id} onclick={()=>switchTab(id as 'users'|'keys'|'audit')}>{label}</button>{/each}</div>
 <p class="hint">Access is managed globally; the realm switcher filters inventory pages. Grants specify each user's realms.</p>
 {#if tab==='audit'}<div class="filters"><label>Actor<input bind:value={actor} onchange={()=>offset=0}/></label><label>Action<input bind:value={actionFilter} onchange={()=>offset=0}/></label><label>From<input type="date" bind:value={since} onchange={()=>offset=0}/></label><label>Through<input type="date" bind:value={until} onchange={()=>offset=0}/></label></div>{/if}
 {#if tab==='keys'}<form class="create" onsubmit={createKey}><label>Key name<input bind:value={keyName} required /></label><label>Scope<select bind:value={scope}><option value="read">Read</option><option value="ingest">Ingest</option><option value="admin">Admin</option></select></label><button disabled={busy}>Create key</button></form>
 {#if createdKey}<section class="panel" aria-label="New API key"><strong>Copy this key now. You won't see this again.</strong><p class="secret">{createdKey}</p><button onclick={copyKey}>{copied?'Copied':'Copy key'}</button><button onclick={()=>createdKey=''}>Dismiss</button></section>{/if}{/if}
 {#if error && !target}<p role="alert">{error}</p>{/if}
 {#if loading}<Skeleton/>{:else if failed}<RetryState retry={()=>revision++}/>{:else if !rows.length}<EmptyState message={tab==='users'?'No users yet.':tab==='keys'?'No API keys yet.':'No audit events match these filters.'}/>{:else}
 <Table label={tab==='users'?'Users':tab==='keys'?'API keys':'Audit log'}><thead><tr>
 {#each (tab==='users'?[['kind','Kind'],['name','Name'],['email','Email'],['login','Last login'],['status','Status']]:tab==='keys'?[['name','Name'],['scope','Scope'],['created','Created']]:[['date','Time'],['actor','Actor'],['action','Action']]) as [field,label]}<th aria-sort={sortState(field)}><button onclick={()=>changeSort(field)}>{label} ↕</button></th>{/each}<th>{tab==='audit'?'Details':'Actions'}</th></tr></thead><tbody>
 {#each rows as row}
 {#if tab==='users'}{@const user=row as User}<tr><td>{user.kind}</td><td>{user.name}</td><td>{user.email ?? '—'}</td><td>{date(user.last_login_at)}</td><td>{user.disabled?'Disabled':'Enabled'}</td><td><div class="actions"><button onclick={()=>edit(user)}>Edit grants</button><button disabled={busy} onclick={()=>setDisabled(user)}>{user.disabled?'Enable':'Disable'}</button></div></td></tr>
 {:else if tab==='keys'}{@const key=row as Key}<tr><td>{key.name}</td><td>{key.scope}</td><td>{date(key.created_at)}</td><td><button onclick={()=>{revoke=key;error='';}}>Revoke</button></td></tr>
 {:else}{@const event=row as Audit}<tr><td>{date(event.occurred_at)}</td><td>{event.actor ?? '—'}</td><td>{event.action}</td><td><details><summary>View details</summary><p>{event.method ?? '—'} · {event.ip ?? '—'}</p><pre>{JSON.stringify(event.detail,null,2)}</pre></details></td></tr>{/if}
 {/each}</tbody></Table>{/if}
 {#if !failed}<Pagination {offset} count={rows.length} {loading} change={(n)=>offset=n}/>{/if}
 {#if target}<section class="panel"><h2>Grants for {target.name}</h2><p>These are individual grants. Configured group grants may also apply.</p><Table label="Grant editor"><thead><tr><th>Role</th>{#each ['*',...availableRealms.filter(r=>r!=='*')] as realm}<th>{realm==='*'?'All realms (*)':realm}</th>{/each}</tr></thead><tbody>{#each ['viewer','editor'] as role}<tr><th scope="row">{role}</th>{#each ['*',...availableRealms.filter(r=>r!=='*')] as realm}<td><input type="checkbox" aria-label={`${role} for ${realm}`} checked={draft.some(g=>g.role===role&&g.realm===realm)} onchange={(e)=>toggle(role,realm,e.currentTarget.checked)}/></td>{/each}</tr>{/each}<tr><th scope="row">admin (all realms)</th><td><input type="checkbox" aria-label="admin for all realms" checked={draft.some(g=>g.role==='admin'&&g.realm==='*')} onchange={(e)=>toggle('admin','*',e.currentTarget.checked)}/></td>{#each availableRealms.filter(r=>r!=='*') as _}<td></td>{/each}</tr></tbody></Table>{#if error}<p role="alert">{error}</p>{/if}<div class="actions"><button disabled={busy} onclick={saveGrants}>Save grants</button><button disabled={busy} onclick={()=>{target=null;error='';}}>Cancel</button></div></section>{/if}
 {#if revoke}<section class="panel"><h2>Revoke {revoke.name}?</h2><p>Clients using this key will lose access.</p><div class="actions"><button disabled={busy} onclick={revokeKey}>Confirm revoke</button><button disabled={busy} onclick={()=>revoke=null}>Cancel</button></div></section>{/if}
</div>
<style>
 .page{margin-top:2rem}.tabs,.actions,.filters,.create{display:flex;gap:.6rem;flex-wrap:wrap;align-items:end}.tabs button[aria-pressed=true]{background:var(--accent-low);color:var(--accent-high)}.hint{color:var(--muted);font-size:.9rem}.filters,.create{margin:1.5rem 0}.filters label,.create label{display:grid;gap:.4rem;font-size:.85rem}select{color:var(--text);background:var(--page);border:1px solid var(--border);padding:.6rem;border-radius:6px}.panel{margin:1.5rem 0;padding:1.2rem;border:1px solid var(--border);border-radius:6px;background:var(--surface)}.panel h2{font-size:1.1rem}.panel .actions{margin-top:1rem}.secret,pre{font-family:var(--font-mono);overflow-wrap:anywhere;white-space:pre-wrap}summary{color:var(--accent-high)}
</style>
