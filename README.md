# rainman

A graph-based recon asset manager. It ingests output from your recon stack
(subdomain/DNS, port scanning, crawling, URL/param discovery) into a single
**property graph** so you can explore, annotate, triage, and hunt across the
whole attack surface from one place.

See [PROPOSAL.md](PROPOSAL.md) for the full design. This repo currently
implements **Phase 0 (Core)**, **Phase 1 (Recon coverage)**, and **Phase 2
(Editor)** — the full importer fleet, the search/filter/status workflow, the
interactive graph UI, and manual editing (nodes/edges, `functionality`
grouping, findings, bulk triage).

## Hunting workflow

The graph is for relationships; day-to-day triage happens in the **Table** view
and from the command line, both driven by one query language.

```bash
rainman import httpx httpx.jsonl          # prints how many assets are new
rainman leads                             # where to look next, with counts
rainman query 'new:last'                  # everything the last import added
rainman query 'type:endpoint code:401|403 -tag:archive' | your-bypass-tool
rainman query 'type:parameter name:redirect*|url|next' --json
```

| Query | Meaning |
|---|---|
| `type:endpoint code:403` | field and prop filters, ANDed (`code` = `status_code`) |
| `code:401\|403`, `code:5*`, `code:>=500` | OR, wildcard, numeric comparison |
| `-tag:archive` | negation |
| `host:api.example.com` | a host and everything under it |
| `tech:nginx` | hosts (and their endpoints) running a technology |
| `new:last`, `new:7d`, `stale:30d` | first seen in the latest import / last 7 days; not seen for 30 days |
| `links:>=4` | number of connections (shared infrastructure) |
| `has:notes`, `has:status_code_history` | has notes / tags / any prop |
| `title:"admin panel"`, bare words | quoted values; substring on value, notes, tags |

Any other `key:value` matches a prop (`reflected:true`, `port:6379`,
`sev:high`, `hunt:working`, …). The same queries work in the UI's Table view
(sortable, multi-select bulk triage, export as a URL list or CSV) and over HTTP
at `GET /nodes?q=…&format=json|txt|csv|jsonl`.

**Leads** are saved hunts shown with live counts in the left panel and by
`rainman leads`: new since last import, 401/403 and 5xx endpoints, status codes
that changed between imports, sensitive paths, dev/staging hosts, reflected and
risky parameter names, JS-sourced and archive-only endpoints, shared
infrastructure, non-web services, stale hosts. They are defined in
`domain/query.py` — add your own there.

## What's built

- **Domain core** (`src/rainman/domain/`) — dependency-free canonical model:
  typed nodes/edges, identity/normalization (the dedupe rule), the triage
  status state machine, and the ports (interfaces) the rest plugs into.
- **SQLite store** (`adapters/store/`) — `GraphRepository` with idempotent
  upsert/dedupe, 1-hop neighbor expansion, search, and digest. Swappable for
  Postgres/Neo4j later since everything goes through the port.
- **Importers** (`adapters/importers/`) — 13 tools, registered by name, each a
  pure mapping from tool output → canonical ops:
  - DNS/hosts: `subfinder`, `shuffledns`, `dnsx`, `httpx`
  - findings: `nuclei` (finding nodes that `affect` the matched endpoint/host)
  - ports: `nmap` (XML), `naabu`
  - crawl + URL discovery: `katana`, `gau`, `waybackurls`
  - content/param discovery: `ffuf`, `kiterunner`, `x8`

  All flow through the same upsert path, so import order is irrelevant and
  re-imports are idempotent (e.g. naabu then nmap enrich one service node).
- **Ingest service** (`domain/ingest.py`) — the single write path; all
  imports/edits funnel through it so dedupe lives in one place. An import is
  one transaction (it fully lands or leaves the graph untouched), malformed
  records are skipped and counted rather than aborting the run, every host is
  linked to its apex domain so nothing is unreachable from the roots, and each
  run is logged so `new:last` can answer "what did that scan add?".
- **HTTP API** (`adapters/api/`) — FastAPI: `digest`, `search`, `node`,
  `neighborhood` (expand-on-click), `import/{tool}`, `ingest`, plus
  status/notes editing with state-machine enforcement.
- **Graph UI + editor** (`adapters/api/static/index.html`) — a single-file
  Cytoscape app served at `/`. Starts at root domains, expands a node's 1-hop
  neighborhood on click (lazy `/neighborhood` fetches), filters by node type and
  status. The detail panel is **editable** (status with legal-transition
  enforcement, tags, notes, delete); **box-select** multiple nodes for bulk
  triage, grouping into a `functionality`, creating a `finding` that `affects`
  them, or linking two nodes by a chosen edge type. No build step / node_modules.
- **Editor ops** (`domain/ingest.py`) — `add_finding`, `create_functionality`,
  `bulk_set_status`, plus edge-by-id linking, all reused by the API (and ready
  for the future MCP server).
- **CLI** (`rainman …`).

> **Store choice:** Phase 0 uses **SQLite** (zero-setup, fits local-first)
> rather than the Postgres/Neo4j options in the proposal. The repository port
> keeps that decision reversible — see `sqlite_repo.py`.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Use

```bash
# import recon output (idempotent — re-importing enriches, never duplicates)
rainman import httpx httpx-out.jsonl
rainman import dnsx  dnsx-out.jsonl

rainman digest                 # counts by type/status + flagged/untriaged
rainman importers              # list available importers
rainman serve --port 8000      # run the API + graph UI
```

Then open **http://localhost:8000** for the graph UI. The CLI and API share a
SQLite file (`--db`, default `rainman.db`).

### Docker

```bash
docker compose up -d --build       # API on http://localhost:8000
```

The API has no login, so compose publishes it on `127.0.0.1` only. The server
sends no CORS headers and refuses cross-origin writes, so other web pages open
in your browser cannot read or modify the graph; if you need it reachable from
another machine, put it behind an SSH tunnel or an authenticating proxy.

The graph persists in the `rainman-data` volume (SQLite at `/data/rainman.db`).
Import recon output into the running container:

```bash
curl -X POST localhost:8000/import/httpx \
  --data-binary @httpx-out.jsonl -H 'content-type: text/plain'
# or run the CLI inside the container against the same DB:
docker compose exec rainman rainman --db /data/rainman.db digest
```

Or build/run the image directly:

```bash
docker build -t rainman:0.1.0 .
docker run -p 8000:8000 -v rainman-data:/data rainman:0.1.0
```

### API tour

```bash
curl localhost:8000/digest
curl "localhost:8000/node?id=sub:api.example.com"          # detail + neighbors
curl "localhost:8000/neighborhood?id=ip:203.0.113.10&types=subdomain"  # shared-infra
curl "localhost:8000/search?q=login&type=endpoint"
curl "localhost:8000/nodes?q=type:endpoint+code:403&format=txt"   # hunter query + export
curl localhost:8000/leads
curl -X POST localhost:8000/import/httpx --data-binary @out.jsonl -H 'content-type: text/plain'
```

## Test

```bash
pytest -q
```

## Upgrading an existing database

Opening an older `rainman.db` migrates it in place. Run `rainman repair` once
to attach hosts imported by earlier versions to their apex domains.

## Next (roadmap)

Still to build from [PROPOSAL.md §17](PROPOSAL.md): the Burp extension, the
MCP agent surface (the query language and leads are its read side), undo and an
audit log, infra clustering and a WebGL renderer for very large graphs.
