import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
// test.css: so tests can read tokens.css as raw text.
export default defineConfig({ plugins: [svelte()], test: { css: true }, server: { proxy: { '/api': 'http://localhost:8080', '/auth': 'http://localhost:8080' } } });
