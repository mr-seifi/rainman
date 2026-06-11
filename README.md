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

## What's built (Phase 0)

- **Domain core** (`src/rainman/domain/`) — dependency-free canonical model:
  typed nodes/edges, identity/normalization (the dedupe rule), the triage
  status state machine, and the ports (interfaces) the rest plugs into.
- **SQLite store** (`adapters/store/`) — `GraphRepository` with idempotent
  upsert/dedupe, 1-hop neighbor expansion, search, and digest. Swappable for
  Postgres/Neo4j later since everything goes through the port.
- **Importers** (`adapters/importers/`) — 11 tools, registered by name, each a
  pure mapping from tool output → canonical ops:
  - DNS/hosts: `shuffledns`, `dnsx`, `httpx`
  - ports: `nmap` (XML), `naabu`
  - crawl + URL discovery: `katana`, `gau`, `waybackurls`
  - content/param discovery: `ffuf`, `kiterunner`, `x8`

  All flow through the same upsert path, so import order is irrelevant and
  re-imports are idempotent (e.g. naabu then nmap enrich one service node).
- **Ingest service** (`domain/ingest.py`) — the single write path; all
  imports/edits funnel through it so dedupe lives in one place.
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
curl -X POST localhost:8000/import/httpx --data-binary @out.jsonl -H 'content-type: text/plain'
```

## Test

```bash
pytest -q
```

## Next (roadmap)

Phase 1 adds the rest of the recon importers (nmap, naabu, katana, gau,
waybackurls, ffuf, kiteRunner, x8) and the read-only graph frontend; later
phases add the editor, the Burp extension, nuclei, scale/clustering, and the
MCP agent surface. See [PROPOSAL.md §17](PROPOSAL.md).
