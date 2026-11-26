<script lang="ts">
 import { api, ApiError } from './api'; import { componentUrl } from './data-pages';
 import { Button, DataTable, EmptyState, ErrorState, Input, Pagination, Panel, Skeleton } from './ui';
 let { realms }: {realms:string[]} = $props();
 type Row = {purl:string,version:string,services:{id:number,name:string,realm:string}[],images:string[]};
 let search=$state(''), below=$state(''), query=$state<{search:string,below:string}|null>(null), offset=$state(0), rows=$state<Row[]>([]), loading=$state(false), failed=$state(''), revision=$state(0);
 const tooShort=$derived(search.trim().length > 0 && search.trim().length < 2);
 $effect(()=>{realms.join(','); offset=0;});
 $effect(()=>{const q=query; revision; if(!q)return; const target=componentUrl(q.search,q.below,realms,offset); let active=true; loading=true; failed='';
  api<Row[]>(target).then(data=>{if(active){rows=data;loading=false;}}).catch((e:unknown)=>{if(active){failed=e instanceof ApiError && e.status===400 && e.code ? e.code : 'retry';loading=false;}}); return ()=>{active=false};});
 function submit(event:SubmitEvent){event.preventDefault(); if(search.trim().length<2)return; offset=0; query={search:search.trim(),below:below.trim()};}
 function clear(){search='';below='';query=null;rows=[];}
</script>
<form class="search" role="search" aria-label="Find a component" onsubmit={submit}>
 <Input label="Find a component" placeholder="log4j-core, pkg:npm/lodash" hint="Package URL text, at least 2 characters." error={tooShort ? 'Type at least 2 characters.' : ''} bind:value={search} />
 <Input label="Versions below" placeholder="2.17.1" hint="Optional. Compared by the package's ecosystem." bind:value={below} />
 <div class="actions"><Button variant="primary" type="submit" disabled={search.trim().length<2}>Search</Button>{#if query}<Button variant="ghost" onclick={clear}>Clear</Button>{/if}</div>
</form>
{#if query}
 <Panel flush>
 {#if loading}<Skeleton/>{:else if failed==='retry'}<ErrorState retry={()=>revision++}/>{:else if failed}<ErrorState message={failed}/>{:else if !rows.length}<EmptyState title="No matching components" body={query.below ? `Nothing matching "${query.search}" below ${query.below} in these realms.` : `Nothing matching "${query.search}" in these realms.`}/>{:else}
  <DataTable label="Matching components"><thead><tr><th>Package URL</th><th>Version</th><th>Services</th><th>Images</th></tr></thead><tbody>{#each rows as row}<tr><td class="mono">{row.purl}</td><td class="mono">{row.version}</td><td><ul>{#each row.services as s}<li><a href={'/services/'+s.id+location.search}>{s.name}</a> <span class="muted">· {s.realm}</span></li>{/each}</ul></td><td>{#if row.images.length}<ul>{#each row.images as image}<li class="mono">{image}</li>{/each}</ul>{:else}<span class="muted">—</span>{/if}</td></tr>{/each}</tbody></DataTable>
 {/if}
 {#if !failed && !loading}<Pagination {offset} count={rows.length} {loading} change={(n)=>offset=n}/>{/if}
 </Panel>
{/if}
<style>.search{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr) auto;gap:var(--s3);align-items:start}.actions{display:flex;gap:var(--s2);padding-top:26px}@media (max-width:720px){.search{grid-template-columns:1fr}.actions{padding-top:0}}ul{margin:0;padding:0;list-style:none;display:grid;gap:2px}.mono{font-family:var(--font-mono);overflow-wrap:anywhere;font-size:var(--text-sm)}.muted{color:var(--muted)}</style>
