<script lang="ts">import ErrorState from '../illustrations/ErrorState.svelte'; let { retry }: { retry: () => void } = $props();</script>
<div role="alert"><ErrorState /><button onclick={retry}>Try again</button></div>
<style>button { margin-top:1rem; }</style>
