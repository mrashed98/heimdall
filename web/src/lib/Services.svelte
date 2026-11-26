<script lang="ts">
 import { api } from './api'; import ComponentSearch from './ComponentSearch.svelte'; import { dailySeries, type TrendRow } from './trends'; import TrendChart from './TrendChart.svelte'; import { dataUrl, nextSort } from './data-pages';
 import { Badge, DataTable, EmptyState, ErrorState, Pagination, Panel, SEVERITIES, Skeleton, Tabs } from './ui';
 let { realms, serviceId }: {realms:string[], serviceId:number|null} = $props();
 type Row = {id:number,name:string,realm:string,critical:number,high:number,medium:number,low:number,unknown:number};
 type Detail = {purl?:string,version?:string,source?:string,digest?:string,image?:string,ref_id?:string,kind?:string,severity?:string,opened_at?:string};
 let info=$state<{name:string,realm:string}|null>(null), trend=$state<TrendRow[]|null>(null), trendFailed=$state(false);
 let spark=$derived(trend ? dailySeries(trend,90).map(d=>({day:d.day,value:d.critical===null ? null : d.critical+(d.high ?? 0)})) : []);
 let rows=$state<Row[]>([]), items=$state<Detail[]>([]), offset=$state(0), sort=$state('realm'), order=$state('asc'), section=$state('components'), loading=$state(true), failed=$state(false), revision=$state(0);
 let url=$derived(dataUrl(serviceId ? `/api/v1/ui/services/${serviceId}/${section}` : '/api/v1/ui/services',realms,offset,sort,order));
 $effect(()=>{realms.join(','); serviceId; offset=0; section='components'; sort=serviceId?'purl':'realm'; order='asc';});
 $effect(()=>{const id=serviceId; const rs=realms.join(','); info=null; if(!id)return; let active=true; api<{name:string,realm:string}[]>(dataUrl(`/api/v1/ui/services/${id}/info`,rs ? rs.split(',') : [],0,'name','asc')).catch(()=>null).then(data=>{if(active)info=data?.[0] ?? null;}); trend=null; trendFailed=false; api<TrendRow[]>(`/api/v1/services/${id}/trend?days=90${rs ? '&realms='+encodeURIComponent(rs) : ''}`).catch(()=>null).then(data=>{if(active){trend=data; trendFailed=data===null;}}); return ()=>{active=false};});
 $effect(()=>{const target=url; revision; let active=true;loading=true;failed=false;api<Row[]|Detail[]>(target).then(data=>{if(active){if(serviceId) items=data as Detail[];else rows=data as Row[];loading=false;}}).catch(()=>{if(active){failed=true;loading=false;}});return ()=>{active=false};});
 function changeSort(field:string){[sort,order]=nextSort(sort,order,field);offset=0;}
 function sortState(field:string):'ascending'|'descending'|'none'{return sort===field?(order==='asc'?'ascending':'descending'):'none';}
 function selectSection(value:string){section=value;offset=0;sort=value==='components'?'purl':value==='images'?'digest':'opened';order='asc';}
</script>
<div class="page">
 {#if serviceId}<a class="back" href={'/services'+location.search}>← All services</a><h2>{info ? info.name : 'Service inventory'}{#if info}<span class="realm"> · {info.realm}</span>{/if}</h2>
  {#if trendFailed}<p class="spark">Trend data could not be loaded.</p>{:else if spark.some(p=>p.value!==null)}<div class="spark"><span>Open critical + high, 90 days</span><TrendChart compact label="Open critical and high findings" color="var(--sev-high)" points={spark}/></div>{/if}
  <Tabs label="Service inventory sections" current={section} change={selectSection} items={[{id:'components',label:'Components'},{id:'images',label:'Images'},{id:'findings',label:'Findings'}]} />{/if}
 {#if !serviceId}<ComponentSearch {realms}/>{/if}
 <Panel flush>
 {#if loading}<Skeleton/>{:else if failed}<ErrorState retry={()=>revision++}/>{:else if serviceId}
  {#if !items.length}<EmptyState title={`No ${section} recorded`} body="Sight, CI uploads and declared components fill this in."/>{:else}<DataTable label={`Service ${section}`}><thead><tr>{#each (section==='components'?[['source','Source'],['purl','Package URL'],['version','Version']]:section==='images'?[['image','Image'],['digest','Digest']]:[['advisory','Advisory'],['severity','Severity'],['kind','Kind'],['opened','Opened']]) as [field,label]}<th aria-sort={sortState(field)}><button onclick={()=>changeSort(field)}>{label}</button></th>{/each}</tr></thead><tbody>{#each items as item}<tr>{#if section==='components'}<td>{item.source}</td><td class="mono">{item.purl}</td><td class="mono">{item.version}</td>{:else if section==='images'}<td class="mono">{item.image ?? 'Image reference unavailable'}</td><td class="mono">{item.digest}</td>{:else}<td class="mono">{item.ref_id ?? '—'}</td><td><Badge severity={item.severity ?? 'unknown'}/></td><td>{item.kind}</td><td>{item.opened_at?.slice(0,10)}</td>{/if}</tr>{/each}</tbody></DataTable>{/if}
 {:else if !rows.length}<EmptyState title="No services yet" body="Services appear once Sight reads your cluster or CI uploads an SBOM."/>{:else}<DataTable label="Services"><thead><tr>{#each [['name','Service'],['realm','Realm'],...SEVERITIES.map(s=>[s,s[0]!.toUpperCase()+s.slice(1)])] as [field,label]}<th aria-sort={sortState(field)}><button onclick={()=>changeSort(field)}>{label}</button></th>{/each}</tr></thead><tbody>{#each rows as row}<tr><td><a href={'/services/'+row.id+location.search}><strong>{row.name}</strong></a></td><td>{row.realm}</td>{#each SEVERITIES as severity}{@const n=row[severity]}<td class:zero={!n} class={n ? severity : ''}>{n}</td>{/each}</tr>{/each}</tbody></DataTable>{/if}
 {#if !failed && !loading}<Pagination {offset} count={serviceId ? items.length : rows.length} {loading} change={(n)=>offset=n}/>{/if}
 </Panel>
</div>
<style>.page{display:grid;gap:var(--s3)}.back{font-size:var(--text-sm)}h2{margin:0;font-size:var(--text-lg)}.realm{color:var(--muted);font-weight:400}.mono{font-family:var(--font-mono);overflow-wrap:anywhere;font-size:var(--text-sm)}.zero{color:var(--muted)}.spark{display:grid;grid-template-columns:auto minmax(0,320px);justify-content:start;gap:var(--s3);align-items:center;font-size:var(--text-sm);color:var(--muted)}.critical{color:var(--sev-critical);font-weight:700}.high{color:var(--sev-high);font-weight:700}.medium{color:var(--sev-medium)}.low{color:var(--sev-low)}</style>
