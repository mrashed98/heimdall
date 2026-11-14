// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

// https://astro.build/config
export default defineConfig({
  site: 'https://mrashed98.github.io',
  base: '/heimdall',
  integrations: [
    starlight({
      title: 'Heimdall',
      description:
        'The watcher at the Bifröst: a lightweight dependency, vulnerability and release tracker for small Kubernetes clusters.',
      logo: { src: './src/assets/logo.svg' },
      favicon: '/favicon.svg',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/mrashed98/heimdall',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/mrashed98/heimdall/edit/main/docs/site/',
      },
      lastUpdated: true,
      customCss: ['./src/styles/custom.css'],
      plugins: [starlightLinksValidator()],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { slug: 'getting-started/what-is-heimdall' },
            { slug: 'getting-started/quick-start' },
            { slug: 'getting-started/kubernetes' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { slug: 'concepts/glossary' },
            { slug: 'concepts/architecture' },
            { slug: 'concepts/matching' },
            { slug: 'concepts/alerts' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { slug: 'guides/ci-gate' },
            { slug: 'guides/oaths' },
            { slug: 'guides/teams' },
            { slug: 'guides/watching-infrastructure' },
            { slug: 'guides/private-registries' },
            { slug: 'guides/monitoring' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: 'reference/configuration' },
            { slug: 'reference/cli' },
            { slug: 'reference/http-api' },
            { slug: 'reference/metrics' },
            { slug: 'reference/helm-values' },
            { slug: 'reference/environment-variables' },
          ],
        },
        {
          label: 'Architecture decisions',
          collapsed: true,
          items: [{ autogenerate: { directory: 'decisions' } }],
        },
        {
          label: 'Project',
          items: [
            { slug: 'project/contributing' },
            { slug: 'project/security' },
            { slug: 'project/license' },
            { slug: 'project/acknowledgements' },
            { slug: 'project/changelog' },
          ],
        },
      ],
    }),
  ],
});
