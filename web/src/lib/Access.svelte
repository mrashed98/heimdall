<script lang="ts">
 import { api, ApiError, type Grant } from './api';
 import { accessUrl, auditFilters } from './access';
 import { nextSort } from './data-pages';
 import { Button, DataTable, EmptyState, ErrorState, Input, Pagination, Panel, Pill, Select, Skeleton, Tabs } from './ui';
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
 <Tabs label="Settings sections" current={tab} change={(id)=>switchTab(id as 'users'|'keys'|'audit')} items={[{id:'users',label:'Members & access'},{id:'keys',label:'API keys'},{id:'audit',label:'Audit log'}]} />
 <p class="hint">Access is global; grants set each member’s realms. The realm picker only filters inventory pages.</p>
 {#if tab==='audit'}<div class="row"><Input label="Actor" bind:value={actor} onchange={()=>offset=0}/><Input label="Action" bind:value={actionFilter} onchange={()=>offset=0}/><Input label="From" type="date" bind:value={since} onchange={()=>offset=0}/><Input label="Through" type="date" bind:value={until} onchange={()=>offset=0}/></div>{/if}
 {#if tab==='keys'}<Panel title="Create an API key"><form class="row" onsubmit={createKey}><Input label="Key name" bind:value={keyName} required /><Select label="Scope" bind:value={scope}><option value="read">Read</option><option value="ingest">Ingest</option><option value="admin">Admin</option></Select><Button type="submit" variant="primary" disabled={busy}>Create key</Button></form>
 {#if createdKey}<section class="secret-box" aria-label="New API key"><strong>Copy this key now. You won’t see it again.</strong><p class="secret">{createdKey}</p><div class="actions"><Button size="sm" onclick={copyKey}>{copied?'Copied':'Copy key'}</Button><Button size="sm" variant="ghost" onclick={()=>createdKey=''}>Dismiss</Button></div></section>{/if}</Panel>{/if}
 {#if error && !target}<p class="error" role="alert">{error}</p>{/if}
 <Panel flush>
 {#if loading}<Skeleton/>{:else if failed}<ErrorState retry={()=>revision++}/>{:else if !rows.length}<EmptyState title={tab==='users'?'No members yet':tab==='keys'?'No API keys yet':'No audit events'} body={tab==='audit'?'No events match these filters.':undefined}/>{:else}
 <DataTable label={tab==='users'?'Members':tab==='keys'?'API keys':'Audit log'}><thead><tr>
 {#each (tab==='users'?[['name','Member'],['kind','Kind'],['email','Email'],['login','Last sign-in'],['status','Status']]:tab==='keys'?[['name','Name'],['scope','Scope'],['created','Created']]:[['date','Time'],['actor','Actor'],['action','Action']]) as [field,label]}<th aria-sort={sortState(field)}><button onclick={()=>changeSort(field)}>{label}</button></th>{/each}<th>{tab==='audit'?'Details':'Actions'}</th></tr></thead><tbody>
 {#each rows as row}
 {#if tab==='users'}{@const user=row as User}<tr><td><strong>{user.name}</strong>{#each user.grants as g}<span class="grant"><Pill tone={g.role==='admin'?'gold':'neutral'}>{g.role} · {g.realm==='*'?'all realms':g.realm}</Pill></span>{/each}</td><td>{user.kind}</td><td>{user.email ?? '—'}</td><td>{date(user.last_login_at)}</td><td class:ok={!user.disabled} class:muted={user.disabled}>{user.disabled?'Disabled':'Active'}</td><td><div class="actions"><Button size="sm" onclick={()=>edit(user)}>Edit grants</Button><Button size="sm" variant={user.disabled?'secondary':'danger'} disabled={busy} onclick={()=>setDisabled(user)}>{user.disabled?'Enable':'Disable'}</Button></div></td></tr>
 {:else if tab==='keys'}{@const key=row as Key}<tr><td><strong>{key.name}</strong></td><td><Pill>{key.scope}</Pill></td><td>{date(key.created_at)}</td><td><Button size="sm" variant="danger" onclick={()=>{revoke=key;error='';}}>Revoke</Button></td></tr>
 {:else}{@const event=row as Audit}<tr><td>{date(event.occurred_at)}</td><td>{event.actor ?? '—'}</td><td class="mono">{event.action}</td><td><details><summary>View details</summary><p class="muted">{event.method ?? '—'} · {event.ip ?? '—'}</p><pre>{JSON.stringify(event.detail,null,2)}</pre></details></td></tr>{/if}
 {/each}</tbody></DataTable>{/if}
 {#if !failed}<Pagination {offset} count={rows.length} {loading} change={(n)=>offset=n}/>{/if}
 </Panel>
 {#if target}<Panel title={`Grants for ${target.name}`}><p class="muted">These are individual grants. Configured group grants may also apply.</p><DataTable label="Grant editor"><thead><tr><th>Role</th>{#each ['*',...availableRealms.filter(r=>r!=='*')] as realm}<th>{realm==='*'?'All realms (*)':realm}</th>{/each}</tr></thead><tbody>{#each ['viewer','editor'] as role}<tr><th scope="row">{role}</th>{#each ['*',...availableRealms.filter(r=>r!=='*')] as realm}<td><input type="checkbox" aria-label={`${role} for ${realm}`} checked={draft.some(g=>g.role===role&&g.realm===realm)} onchange={(e)=>toggle(role,realm,e.currentTarget.checked)}/></td>{/each}</tr>{/each}<tr><th scope="row">admin (all realms)</th><td><input type="checkbox" aria-label="admin for all realms" checked={draft.some(g=>g.role==='admin'&&g.realm==='*')} onchange={(e)=>toggle('admin','*',e.currentTarget.checked)}/></td>{#each availableRealms.filter(r=>r!=='*') as _}<td></td>{/each}</tr></tbody></DataTable>{#if error}<p class="error" role="alert">{error}</p>{/if}<div class="actions top"><Button variant="primary" disabled={busy} onclick={saveGrants}>Save grants</Button><Button variant="ghost" disabled={busy} onclick={()=>{target=null;error='';}}>Cancel</Button></div></Panel>{/if}
 {#if revoke}<Panel title={`Revoke ${revoke.name}?`}><p class="muted">Clients using this key will lose access.</p><div class="actions top"><Button variant="danger" disabled={busy} onclick={revokeKey}>Confirm revoke</Button><Button variant="ghost" disabled={busy} onclick={()=>revoke=null}>Cancel</Button></div></Panel>{/if}
</div>
<style>
 .page{display:grid;gap:var(--s3)}.row,.actions{display:flex;gap:var(--s2);flex-wrap:wrap;align-items:end}.top{margin-top:var(--s3)}.hint,.muted{color:var(--muted)}.hint{font-size:var(--text-sm);margin:0}.error{color:var(--sev-high);margin:0}.ok{color:var(--ok)}.grant{display:inline-block;margin:2px 0 0 6px}.mono{font-family:var(--font-mono);font-size:var(--text-sm)}
 .secret-box{margin-top:var(--s3);padding:var(--s3);border:1px solid var(--gold-line);background:var(--gold-soft);border-radius:var(--r-control);display:grid;gap:var(--s2)}.secret,pre{font-family:var(--font-mono);overflow-wrap:anywhere;white-space:pre-wrap;margin:0}summary{color:var(--gold)}
</style>
