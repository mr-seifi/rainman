# rainman — Design System

A design reference for Claude Code. All UI work should derive from these tokens and patterns. Do not introduce colors, type sizes, or components that aren't defined here.

---

## Philosophy

- **Dark-first, terminal-adjacent.** This is a tool used during active recon sessions, not a consumer dashboard. Every decision favors density and legibility over decoration.
- **Monospace for data, sans-serif for prose.** Node IDs, paths, status codes, IPs, response sizes → mono. Labels, notes, descriptions → sans.
- **Color encodes meaning, never sequence.** Each node type, status, and severity has a fixed color. Never use these colors for anything else.
- **No gradients, shadows, or glow effects.** Flat surfaces only. A single 1px border at low opacity is the only elevation signal.

---

## Color Tokens

### Base surfaces

```
--bg-canvas:    #0D0F10   /* graph canvas background */
--bg-panel:     #111416   /* side panels, detail panes */
--bg-elevated:  #1C2026   /* cards, node detail blocks */
--bg-raised:    #262B33   /* hover states, inline tags */
```

### Brand / accent

```
--color-live:   #22FF8F   /* phosphor green — live/active assets, primary actions */
--color-live-dim: #0D6639
--color-live-dimmer: #071F12
```

### Node type colors

```
--color-program:     #22FF8F  / bg: #071F12  / border: #0D6639
--color-domain:      #60A8FF  / bg: #0D1622  / border: #1A3D6B
--color-subdomain:   #4A9EFF  / bg: #0D1622  / border: #173A6B
--color-ip:          #F5B942  / bg: #1A1A0D  / border: #6B4A0F
--color-asn:         #C8A840  / bg: #1A1A0D  / border: #4A3A10
--color-service:     #3ECFA0  / bg: #0F1A14  / border: #0C3D2A
--color-endpoint:    #8B7CF8  / bg: #1A0F1A  / border: #2E2268
--color-parameter:   #B09EFA  / bg: #261A30  / border: #3A2870
--color-technology:  #E07070  / bg: #1A1414  / border: #4A2020
--color-certificate: #5ABCEF  / bg: #0D1620  / border: #143050
--color-finding:     #F05656  / bg: #1A0808  / border: #5C1A1A
--color-functionality: #FF6B35 / bg: #1A130D / border: #7A2E10
```

### Status colors

```
--color-untriaged:   #8B95A1  / bg: #1A1E24  / border: #2A3040
--color-in_scope:    #22FF8F  / bg: #071F12  / border: #0D6639
--color-testing:     #4A9EFF  / bg: #0D1622  / border: #173A6B
--color-flagged:     #FF6B35  / bg: #1A130D  / border: #7A2E10
--color-confirmed:   #F05656  / bg: #1A0808  / border: #5C1A1A
--color-done:        #6070A0  / bg: #12121A  / border: #202840
--color-ignored:     #404555  / bg: #141414  / border: #202228
--color-oos:         #404555  / bg: #141414  / border: #202228  (strikethrough text)
```

### Severity colors

```
--color-sev-info:     #5ABCEF  / bg: #0D1622  / border: #173A6B
--color-sev-low:      #3ECFA0  / bg: #0F1A14  / border: #0C3D2A
--color-sev-medium:   #F5B942  / bg: #1A1300  / border: #6B4A0F
--color-sev-high:     #FF6B35  / bg: #1A0F08  / border: #7A2E10
--color-sev-critical: #F05656  / bg: #1A0808  / border: #5C1A1A
```

### Text

```
--text-primary:   #E8EDF2
--text-secondary: #8B95A1
--text-dim:       #4A5260
```

### Borders

```
--border:    #1E2530   /* default */
--border-hi: #2A3444   /* hover / focus */
```

---

## Typography

```
--font-mono: 'JetBrains Mono', 'Fira Mono', 'Cascadia Code', 'Courier New', monospace
--font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif
```

### Scale

| Role | Font | Size | Weight |
|---|---|---|---|
| Section label / eyebrow | sans | 10px | 600 — ALL CAPS, letter-spacing 0.12em |
| Body / prose | sans | 13px | 400 |
| Node title | mono | 13px | 600 |
| Node subtitle / ID | mono | 11px | 400 — text-secondary |
| Badge / chip text | mono | 11px | 500 |
| Endpoint path | mono | 11px | 400 |
| HTTP method | mono | 10px | 700 |
| Status code | mono | 10px | 600 |
| Source pill | mono | 9px | 400 |
| Digest count | mono | 20px | 600 |
| Digest label | mono | 10px | 400 |
| CLI / code block | mono | 11px | 400 — line-height 1.9 |
| Notes / italic prose | sans | 10–11px | 400 — italic, text-dim |

---

## Border Radius

```
--r:    6px   /* badges, chips, rows, inputs */
--r-lg: 10px  /* cards, panels, node detail blocks */
--r-pill: 20px /* status chips with dot */
```

---

## Component Patterns

### Node type badge

Used in: search results, graph legend, detail panel breadcrumbs, finding cards.

```html
<span class="node-badge nb-{type}">
  <span class="dot"></span>
  {type}
</span>
```

Structure: `background` from node bg token, `color` from node color token, `border` 1px solid node border token, `border-radius: var(--r)`, `font-family: mono`, `font-size: 11px`, `font-weight: 500`, `padding: 5px 10px`. Dot is 7×7px circle, same color as text.

### Status chip

```html
<span class="status-chip sc-{status}">
  <span class="dot"></span>
  {status}
</span>
```

Structure: `border-radius: var(--r-pill)` (20px), `padding: 4px 10px`. Colors from status tokens above. `out_of_scope` gets `text-decoration: line-through`.

### Severity chip

```html
<span class="sev-{level}">{level}</span>
```

Structure: `border-radius: var(--r)`, `padding: 3px 10px`, `font-size: 10px`, `font-weight: 600`, `letter-spacing: 0.05em`, `text-transform: uppercase`. Colors from severity tokens above.

### Node detail card

```
┌─────────────────────────────────────────────┐
│ [node-badge]              [status-chip]      │
│                                              │
│ node.value                                   │  ← mono 13px 600
│ node.id (canonical key)                      │  ← mono 11px text-secondary
│                                              │
│ ─────────────────────────────────────────── │
│ Key          Value                           │  ← row: sans 11px dim / mono 11px
│ Key          Value                           │
│ ...                                          │
│                                              │
│ [tag] [tag] [tag]                            │  ← bg-raised, mono 10px, r=3px
│                                              │
│ Notes text here...                           │  ← sans 10px italic text-dim
│                                              │
│ [source-pill] [source-pill]                  │
└─────────────────────────────────────────────┘
```

Card: `background: var(--bg-panel)`, `border: 1px solid var(--border-hi)`, `border-radius: var(--r-lg)`, `padding: 14px 16px`. Row dividers: `border-top: 1px solid var(--border)`.

Colored values: IPs → `--color-subdomain`, live status codes → `--color-live`, counts with issues → `--color-flagged`.

### Finding card

```
┌─────────────────────────────────────────────┐  ← border: var(--color-finding border)
│ Finding title                [sev-chip]      │
│ [status-chip]                                │
│                                              │
│ Prose description of the finding...          │
│                                              │
│ [node-badge affected]  [author-tag]          │
└─────────────────────────────────────────────┘
```

### Endpoint list row

```
[METHOD] /path/to/endpoint          [status] [size]
```

- Row: `background: var(--bg-elevated)`, `border-radius: var(--r)`, `border: 1px solid transparent`, hover → `border-color: var(--border-hi)`, `background: var(--bg-raised)`
- Method badge: `font-size: 10px`, `font-weight: 700`, fixed `width: 36px`, centered, `border-radius: 3px`, `padding: 2px 0`
  - GET → `color: #22FF8F`, `background: #071F12`
  - POST → `color: #F5B942`, `background: #1A1000`
  - PUT → `color: #4A9EFF`, `background: #0A1A2E`
  - DELETE → `color: #F05656`, `background: #1A0A0A`
  - PATCH → same as PUT
- Path: mono 11px text-secondary, flex 1
- Status code: mono 10px 600, width 28px, right-aligned
  - 2xx → `--color-live`
  - 3xx → `--color-subdomain`
  - 4xx (403) → `--color-flagged`
  - 4xx (404) → `--text-secondary`
  - 5xx → `--color-finding`
- Size: mono 10px text-dim, width 52px, right-aligned

### Source pill

```html
<span class="source-pill">
  <span class="source-dot"></span>
  {tool-name}
</span>
```

Structure: `background: var(--bg-raised)`, `border: 1px solid var(--border)`, `border-radius: 3px`, mono 9px text-dim. Dot 5×5px circle.

Dot color by source category:
- DNS/live (shuffledns, dnsx, httpx) → `--color-live`
- Ports (nmap, naabu) → `--color-subdomain`
- Crawl/URL (katana, gau, waybackurls) → `--color-endpoint`
- Params (ffuf, x8, kiterunner) → `--color-parameter`
- Findings (nuclei) → `--color-finding`
- Manual testing (burp-ext) → `--color-flagged`
- Manual/editor → `--color-endpoint` at 50% opacity

### Author tag (provenance)

```html
<span class="author-tag">⚡ burp-ext</span>
<span class="author-tag agent">🤖 agent · 0.72</span>
```

Structure: mono 9–10px, `background: var(--bg-raised)`, `border-radius: 3px`, `padding: 2px 6px`, `color: var(--text-dim)`. Agent variant → `color: var(--color-endpoint)`, `background: var(--color-endpoint bg)`.

### Digest / metric card

```
┌────────────────┐
│ 247            │  ← mono 20px 600
│ subdomains     │  ← mono 10px text-dim
└────────────────┘
```

Structure: `background: var(--bg-elevated)`, `border-radius: var(--r)`, `border: 1px solid var(--border)`, `padding: 10px 12px`. Flagged count → `--color-flagged`. Confirmed count → `--color-finding`. Use in 4-column grid.

### Search bar

```
[search-icon]  [input placeholder]          [⌘K]
```

Structure: `background: var(--bg-elevated)`, `border: 1px solid var(--border-hi)`, `border-radius: var(--r)`, `padding: 8px 12px`. Input: mono 12px, no border, transparent bg, placeholder → text-dim.

Filter chips below: `background: var(--bg-raised)`, `border: 1px solid var(--border-hi)`, mono 10px. Active chip → node type or status colors.

### Buttons

| Variant | Background | Text | Border |
|---|---|---|---|
| primary (import/ingest) | `--color-live-dimmer` | `--color-live` | `--color-live-dim` |
| secondary (add/link) | `--color-ip bg` | `--color-subdomain` | `--color-ip border` |
| ghost | transparent | text-secondary | `--border-hi` |
| danger | transparent | `--color-finding` | `--color-finding border` |

All buttons: `font-size: 12px`, `font-weight: 500`, `border-radius: var(--r)`, `padding: 6px 14px`, `border: 1px solid`. Icon buttons: `padding: 6px 8px`. Small variant: `padding: 4px 10px`, `font-size: 11px`.

### CLI code block

```
background: var(--bg-canvas)
border: 1px solid var(--border)
border-radius: var(--r)
padding: 12px 14px
font-family: mono
font-size: 11px
line-height: 1.9
```

Syntax coloring in CLI blocks:
- Command (`rainman`) → `--color-live`
- Subcommand (`import`, `serve`, `digest`) → `--color-subdomain`
- Tool name argument (`httpx`, `dnsx`) → `--color-ip`
- File path / flags → text-secondary
- `$` prompt → text-dim

---

## Triage State Machine

Legal transitions only. Enforce server-side; the UI reflects these rules.

```
untriaged → in_scope → testing → flagged → confirmed → done
                                         ↘ ignored
                                         ↘ out_of_scope
```

- Forward progression only within the main chain
- `ignored` and `out_of_scope` are exit states reachable from any active state
- `done` is terminal (no transitions out)
- Nodes in `out_of_scope` are hidden from graph by default (filtered out)
- Status displayed as a `status-chip` with the dot + colored pill pattern

---

## Graph Canvas (Cytoscape / Sigma)

### Node rendering

Each node type maps to a shape + color in the graph:

| Type | Shape | Color |
|---|---|---|
| program | rectangle | `--color-program` |
| domain | rounded rect | `--color-domain` |
| subdomain | ellipse | `--color-subdomain` |
| ip | diamond | `--color-ip` |
| asn | hexagon | `--color-asn` |
| service | rectangle | `--color-service` |
| endpoint | circle | `--color-endpoint` |
| parameter | small circle | `--color-parameter` |
| technology | triangle | `--color-technology` |
| certificate | rectangle | `--color-certificate` |
| finding | star / octagon | `--color-finding` |
| functionality | rounded rect | `--color-functionality` |

### Edge rendering

| Edge type | Stroke | Style |
|---|---|---|
| resolves_to | `--color-live` dim | solid |
| subdomain_of | `--color-live` dim | solid |
| cname_to | text-dim | dashed |
| runs_service | `--color-subdomain` | solid |
| has_endpoint | `--color-endpoint` | solid |
| has_param | `--color-parameter` | solid |
| affects | `--color-finding` | solid |
| part_of | `--color-flagged` | solid |
| shares_cert | text-dim | dashed |
| announced_by | `--color-ip` | solid |
| uses_tech | `--color-technology` dim | dotted |

Stroke width: 1px default, 1.5px for `affects` and `resolves_to`.

### Interaction states

- **Default**: node at 70% opacity, edge at 40% opacity
- **Hover**: node at 100%, connected edges at 80%, a 1px `--color-live` ring at 30% opacity around hovered node
- **Selected**: node at 100%, 1px `--color-live` ring at 80%, detail panel opens
- **Filtered-out**: 15% opacity, not clickable

### Expand-on-click

The graph is lazy — it starts with root `program`/`domain` nodes only. Clicking any node fetches its 1-hop neighborhood from `GET /neighborhood?id={id}` and merges new nodes/edges into the canvas. A loading indicator (small spinner in the node) shows during fetch.

### Scale thresholds

- ≤ 500 visible nodes → Cytoscape.js (SVG renderer)
- \> 500 visible nodes → Sigma.js (WebGL renderer)

Both implement the same visual spec. The switch is seamless to the user.

---

## Layout — Main Application

```
┌──────────────────────────────────────────────────┬───────────────┐
│  [logo]  [program selector]  [search]   [import] │               │
├──────────────────────────────────────────────────┤  detail panel │
│                                                  │               │
│                                                  │  (slides in   │
│            graph canvas                          │   on node     │
│                                                  │   click)      │
│                                                  │               │
│                                                  │               │
├──────────────────────────────────────────────────┤               │
│ [type filters]  [status filters]  [source filters│               │
└──────────────────────────────────────────────────┴───────────────┘
```

- Topbar: `height: 48px`, `background: var(--bg-panel)`, `border-bottom: 1px solid var(--border)`
- Detail panel: `width: 340px`, slides in from right on node select, `background: var(--bg-panel)`, `border-left: 1px solid var(--border)`
- Bottom filter bar: `height: 40px`, `background: var(--bg-panel)`, `border-top: 1px solid var(--border)`
- Graph canvas: fills remaining space, `background: var(--bg-canvas)`

---

## Layout — Editor Page

```
┌───────────────┬──────────────────────────┬───────────────┐
│  node list /  │                          │  properties   │
│  search       │    graph (editable)      │  panel        │
│               │                          │               │
│  [+ add node] │  drag to reposition      │  edit fields  │
│               │  right-click for menu    │  add edges    │
└───────────────┴──────────────────────────┴───────────────┘
```

---

## Provenance & Author Attribution

Every node, edge, and finding carries `author_type: human | tool | agent`. Display rules:

| Author | Visual treatment |
|---|---|
| tool (any importer) | source pill with tool name |
| human (editor / Burp) | source pill "manual" or "burp-ext" |
| agent (LLM) | author-tag with 🤖 icon + confidence score |

Agent-authored findings: always show confidence (e.g. `0.72`). Agent nodes/edges pending review appear with a dashed border instead of solid. Review queue items get a subtle `--color-flagged` left border accent on the detail card.

---

## Spacing

| Token | Value | Usage |
|---|---|---|
| `--gap-xs` | 4px | inline icon gaps, dot spacing |
| `--gap-sm` | 8px | between chips/pills, row padding |
| `--gap-md` | 12px | card padding internal, grid gap |
| `--gap-lg` | 16px | between sections within a panel |
| `--gap-xl` | 24px | between major layout regions |

---

## Do / Don't

**Do:**
- Use mono for every piece of data (IDs, paths, codes, sizes, hashes)
- Keep borders 1px and at low opacity (use the `--border` token, never pure white)
- Let node type color be the primary visual encoding in the graph — don't add extra decoration
- Show `author_type` on all agent-contributed data
- Enforce state machine transitions — never allow arbitrary status changes in the UI
- Lazy-load the graph (expand on click, never load everything)

**Don't:**
- Use gradients, drop shadows, glow effects, or blur
- Introduce new colors outside the palette — extend the token list if a new node type is added
- Display the full graph on load — it will not scale
- Mix sans-serif into data display (endpoint paths, node IDs, status codes)
- Omit source attribution from imported nodes
- Allow free-form status strings — the state machine has 8 valid values, enforce them
