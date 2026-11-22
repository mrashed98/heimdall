import { mount } from 'svelte';
import '@fontsource/cinzel/latin-700.css';
import './lib/ui/tokens.css';
import App from './App.svelte';
mount(App, { target: document.getElementById('app')! });
