# Heimdall documentation site

Built with [Astro Starlight](https://starlight.astro.build) (search is Pagefind,
built in). Published to <https://mrashed98.github.io/heimdall/> by
`.github/workflows/docs.yml`.

## Run it locally

You need Node 22 or newer (`>=22.23.4`).

```bash
cd docs/site
npm install
npm run dev        # http://localhost:4321/heimdall/
```

Other commands:

| Command | What it does |
|---|---|
| `npm run build` | Production build into `dist/`, including the search index. Fails on broken internal links. |
| `npm run preview` | Serve the built site at <http://localhost:4321/heimdall/>. Search only works here, not in `dev`. |
| `npm run sync-adrs` | Copy `docs/adr/*.md` into the site (runs automatically before `dev` and `build`). |

## Layout

- `src/content/docs/`: the pages (`.md` and `.mdx`). The sidebar is defined in
  `astro.config.mjs`.
- `src/content/docs/decisions/`: the ADR pages are **generated** from
  `docs/adr/` and gitignored. Only `index.md` there is hand-written.
- `src/styles/custom.css` and `src/assets/logo.svg`: theme and logo.

## Writing rules

- Every flag, key, metric and route must be checked against the source code.
- Link internal pages with the base path: `/heimdall/section/page/`.
- Keep it plain and friendly; the audience includes people new to Rust and Kubernetes.
