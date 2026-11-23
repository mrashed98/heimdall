<script lang="ts">
  import { PAGE_SIZE } from '../data-pages';
  let { offset, count, loading, change }: { offset: number; count: number; loading: boolean; change: (offset: number) => void } = $props();
</script>
<nav class="pages" aria-label="Pages">
  <span>{count ? `${offset + 1}–${offset + count}` : loading ? '' : 'No rows on this page'}</span>
  <button disabled={offset === 0 || loading} onclick={() => change(Math.max(0, offset - PAGE_SIZE))}>Previous</button>
  <button disabled={count < PAGE_SIZE || loading} onclick={() => change(offset + PAGE_SIZE)}>Next</button>
</nav>
<style>
  .pages { display: flex; align-items: center; justify-content: flex-end; gap: var(--s2); padding: var(--s3) var(--s4); color: var(--muted); font-size: var(--text-sm); }
  span { margin-right: auto; }
  button { border: 1px solid var(--border); background: var(--panel-2); border-radius: var(--r-control); padding: 5px 12px; font-weight: 600; }
  button:disabled { opacity: .5; cursor: not-allowed; }
</style>
