<script lang="ts">
 import { PAGE_SIZE } from '../data-pages';
 let { offset, count, loading, change }: {offset:number, count:number, loading:boolean, change:(offset:number)=>void} = $props();
</script>
<div class="pagination"><button disabled={offset===0 || loading} onclick={() => change(Math.max(0, offset-PAGE_SIZE))}>Previous</button><span>{count ? `Rows ${offset+1}–${offset+count}` : 'No rows on this page'}</span><button disabled={count<PAGE_SIZE || loading} onclick={() => change(offset+PAGE_SIZE)}>Next</button></div>
<style>.pagination{display:flex;align-items:center;gap:1rem;margin:1rem 0;color:var(--muted);font-size:.85rem}</style>
