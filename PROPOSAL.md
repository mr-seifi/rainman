# Asset Mapper — Design Proposal

A graph-based recon asset manager that ingests output from your recon and
discovery stack — subdomain/DNS, port scanning, crawling, and URL/content/
parameter discovery (shuffledns, dnsx, nmap, naabu, httpx, katana, gau,
waybackurls, ffuf, kiteRunner, x8, …) plus nuclei and Burp Suite — links
everything into a single property graph, and lets you annotate, triage, and
hunt across the whole attack surface from one place.

---

## 1. Summary

Recon produces a pile of disconnected lists — subdomains here, open ports
there, live URLs in another file, Burp history in a fourth. The interesting
bugs live in the *relationships between* those lists (two subdomains on one
host, a forgotten dev box, an endpoint that shows up across five hosts), and
no list view surfaces them.

This tool models the attack surface as a **property graph**, feeds it
automatically from your existing tools, and gives you:

- An interactive graph you explore by expanding nodes on click.
- A detail panel per node (endpoints, status codes, tech, your notes, status).
- An editor for manual structure — grouping endpoints into *functionalities*,
  linking findings to the assets they affect, flagging suspicions.
- A Burp Suite extension that pushes live traffic into the graph as you test.

It is **not** a scanner and **not** a Burp replacement. It is the layer that
sits *above* your recon tools and *beside* Burp, holding the map.

---

## 2. Problem & motivation

| Gap today | What this tool does |
|---|---|
| Recon output is flat files that don't talk to each other | Normalizes everything into one linked graph |
| Shared infrastructure (same IP/ASN/cert) is invisible in lists | Drawn as explicit edges — the hairball *is* the insight |
| Burp organizes *requests*, not *assets* | Asset-level inventory; Burp data feeds in as endpoints |
| Notes/suspicions scatter across tools and text files | Notes + status live on the node, queryable |
| No structure for "this feature spans these 6 endpoints" | User-defined `functionality` nodes |

---

## 3. Goals & non-goals

**Goals**

- One canonical, deduplicated graph of the attack surface per target/program.
- Automatic ingestion across the recon stack — DNS, port scanning, crawling,
  and URL/content/parameter discovery (shuffledns, dnsx, nmap, naabu, httpx,
  katana, gau, waybackurls, ffuf, kiteRunner, x8) plus nuclei and Burp.
- Expand-on-click exploration that scales to thousands of nodes.
- Manual editing: add/edit nodes and edges, group functionalities, triage status.
- A Burp extension that captures and pushes traffic with one keypress.

**Non-goals (at least for v1)**

- Running the recon tools for you (you run them; the tool imports results).
- Being a vulnerability scanner.
- Multi-tenant SaaS. Start single-user / local-first.

---

## 4. Core concept: the property graph

Everything is a **typed node** with a **property bag**, connected by
**typed edges**. The schema is about *relationships*, never about hard-coding
specific asset kinds — so adding "S3 bucket" or "GraphQL schema" later is a new
node type, not a migration.

### Node types

| Type | Represents | Key source |
|---|---|---|
| `program` | Top-level target / scope | manual |
| `domain` | Apex domain (`example.com`) | manual / scope |
| `subdomain` | FQDN host (`api.example.com`) | shuffledns, dnsx, httpx |
| `ip` | IPv4/IPv6 address | dnsx, httpx, nmap |
| `asn` | Autonomous system | dnsx / enrichment |
| `service` | Open port + protocol + banner | nmap |
| `endpoint` | A URL path (`/v2/users`) | httpx, Burp |
| `parameter` | Query/body/header/path param | Burp, manual |
| `technology` | Detected fingerprint (nginx, WP) | httpx |
| `certificate` | TLS cert (SANs link hosts) | httpx |
| `finding` | Suspected or confirmed issue | nuclei, manual |
| `functionality` | User-defined feature/flow | manual |

### Edge types

| Edge | From → To |
|---|---|
| `subdomain_of` | subdomain → domain |
| `resolves_to` | subdomain → ip |
| `cname_to` | subdomain → subdomain/domain |
| `announced_by` | ip → asn |
| `runs_service` | ip → service |
| `has_endpoint` | subdomain → endpoint |
| `has_param` | endpoint → parameter |
| `uses_tech` | subdomain/endpoint → technology |
| `shares_cert` | subdomain → certificate → subdomain |
| `affects` | finding → (any node) |
| `part_of` | endpoint/param → functionality |

---

## 5. Data model / schema

### Node (canonical shape)

```json
{
  "id": "sub:api.example.com",
  "type": "subdomain",
  "value": "api.example.com",
  "status": "flagged",
  "tags": ["api", "auth"],
  "notes": "REST API v2, JWT. No rate-limit on /login. Revisit.",
  "first_seen": "2026-06-10T08:12:00Z",
  "last_seen":  "2026-06-11T19:40:00Z",
  "sources": ["shuffledns", "dnsx", "httpx"],
  "props": {
    "resolvable": true,
    "cname": null,
    "wildcard": false
  }
}
```

- `id` is a **natural key** built from the normalized value
  (`sub:` + lowercased FQDN, trailing dot stripped). This makes upsert/dedupe
  trivial — re-importing the same host updates rather than duplicates.
- `status` drives triage workflow:
  `untriaged → in_scope → testing → flagged → confirmed → done | ignored | out_of_scope`.
- `props` is the only type-specific part; everything else is shared.

### Type-specific `props` examples

| Type | Notable props |
|---|---|
| `ip` | `ptr`, `org`, `cloud`, `cdn` |
| `service` | `port`, `protocol`, `state`, `product`, `version`, `banner` |
| `endpoint` | `method`, `status_code`, `content_length`, `content_type`, `title`, `screenshot_ref` |
| `parameter` | `location` (query/body/header/path), `example`, `reflected` |
| `finding` | `severity`, `vuln_class`, `confidence`, `template_id`, `poc_ref` |
| `functionality` | `name`, `description`, `risk_notes` |

### Edge

```json
{
  "id": "edge:resolves:api.example.com:203.0.113.10",
  "type": "resolves_to",
  "from": "sub:api.example.com",
  "to": "ip:203.0.113.10",
  "sources": ["dnsx"],
  "first_seen": "2026-06-10T08:12:00Z",
  "props": {}
}
```

---

## 6. Architecture

```
   recon + discovery tools             live testing
 (subdomains · DNS · ports ·           (Burp Suite)
  crawl · URLs · content ·                  |
  params — see §7 for list)                 |
        |  JSON/XML                           |  Montoya API
        v                                      v
 +----------------+   push    +-------------------------+
 |  Collectors    |---------->|   Burp Extension        |
 |  (CLI import + |           |  (Kotlin, capture+tag)  |
 |  file watch)   |           +-----------+-------------+
 +-------+--------+                       |
         |  normalize + upsert            |  HTTP POST /ingest
         v                                v
 +--------------------------------------------------+
 |               Backend API (FastAPI)              |
 |  ingest · dedupe · graph queries · mutations     |
 +-----------------------+--------------------------+
                         |
                         v
              +---------------------+
              |   Graph store        |
              |  Neo4j  *or*         |
              |  Postgres + edges    |
              +---------------------+
                         ^
                         |  REST / GraphQL
                         v
 +--------------------------------------------------+
 |        Frontend (React)                          |
 |  Graph view (Cytoscape/Sigma) · detail panel ·   |
 |  editor page · filters · search                  |
 +--------------------------------------------------+
```

**Components**

1. **Collectors** — small importers, one per tool, that parse output and emit
   normalized nodes/edges. Run as `mapper import httpx out.json` or as a folder
   watcher that auto-ingests new result files.
2. **Backend API** — the single writer. Handles dedupe/upsert, serves graph
   queries (neighborhood expansion, node detail), and accepts mutations from
   the editor and the Burp extension.
3. **Store** — the property graph (see §13 for the DB choice).
4. **Frontend** — graph exploration + detail panel + editor.
5. **Burp extension** — pushes live traffic into the same `/ingest` endpoint.

---

## 7. Tool integrations

Each integration is a pure mapping from tool output → nodes + edges. All of
them flow through the same upsert path, so order of import doesn't matter and
re-imports are idempotent.

| Tool | Output format | Produces |
|---|---|---|
| **shuffledns** | resolved FQDN list (massdns) | `subdomain` nodes + `subdomain_of` edges; `resolves_to` if A records are included |
| **dnsx** | `-json`: `a`, `aaaa`, `cname`, `ptr`, `ns`, `mx` | `ip` nodes, `resolves_to` + `cname_to` edges, `ptr` prop on IPs |
| **httpx** | `-json`: `url`, `status_code`, `title`, `tech[]`, `webserver`, `content_length`, `ip`, `cdn`, `tls.subject_an[]` | enriches `subdomain`/`endpoint` (status code, title), `technology` nodes + `uses_tech`, `certificate` node + `shares_cert` from SAN list |
| **katana** | `-json`/`-jsonl`: `request.endpoint`, `request.method`, `response.status_code`, `request.source` | crawled `endpoint` nodes + `has_endpoint` edges; extracted query/form params → `parameter` nodes + `has_param`; JS-sourced endpoints flagged via `source` |
| **gau** | URL list / `--json` (Wayback, OTX, Common Crawl, URLScan) | passive/archived `endpoint` nodes + `has_endpoint`; query params → `parameter` nodes; tagged `source=archive` (not probed — pair with httpx for live status) |
| **waybackurls** | URL list (Wayback Machine only) | same as gau, Wayback-only; dedupes into the same archived `endpoint`/`parameter` nodes |
| **ffuf** | `-of json`: `results[].url`, `status`, `length`, `words`, `input` (FUZZ value) | content-discovery `endpoint` nodes (status, length) + `has_endpoint`; vhost-mode hits → `subdomain` nodes; param-fuzz hits → `parameter` nodes |
| **kiteRunner (kr)** | `-j` JSON: `url`, `status`, `length` | API-focused `endpoint` nodes (status, length) + `has_endpoint`; route-based hits tagged `kind=api` |
| **x8** | `-O json`: discovered params per URL (`name`, location, `reflected`) | `parameter` nodes + `has_param` edges, carrying `location` (query/body/header) and the `reflected` flag |
| **recollapse** | payload/wordlist generator (produces no assets itself) | not a direct importer — feeds ffuf/x8/kr; successful hits arrive through those and get tagged `technique=recollapse` for provenance |
| **nmap** | `-oX` XML | `service` nodes (`port`, `protocol`, `state`, `product`, `version`) + `runs_service` edges off the IP |
| **naabu** | `-json`: `host`, `ip`, `port`, `protocol` | fast `service` nodes (`port`, `protocol`, `state=open`) + `runs_service` edges; pipe to nmap for product/version detail |
| **nuclei** | `-json`: `template-id`, `info.severity`, `matched-at` | `finding` nodes + `affects` edges to the matched host/endpoint |
| **Burp ext** | live request/response | `endpoint` + `parameter` nodes, `status_code`, request/response refs, manual tags/status |

**Example: one httpx record → graph**

```
httpx line:  {"url":"https://api.example.com/v2/users",
              "status_code":200,"tech":["nginx","Node.js"],
              "ip":"203.0.113.10","tls":{"subject_an":["*.example.com"]}}

becomes:
  endpoint:api.example.com/v2/users   (status_code=200)
  technology:nginx, technology:Node.js   + uses_tech edges
  ip:203.0.113.10   + resolves_to edge (if new)
  certificate:*.example.com   + shares_cert edge
```

---

## 8. Burp Suite extension

A first-class part of the system, not an afterthought.

- **Stack:** Kotlin on the **Montoya API** (current Burp extension API).
- **Capture:** registers an HTTP handler so proxied/repeated traffic can be
  pushed; plus a context-menu action ("Send to Asset Mapper", hotkey) for
  selected requests, mirroring how Organizer's "Send to" already works.
- **What it sends:** host, path, method, status code, response length/type,
  detected params, and any note/highlight/status you set in Burp — posted as
  JSON to the backend `/ingest` endpoint.
- **Two-way (stretch):** pull the node's existing notes/status back into a Burp
  tab so the graph's context shows up while you test.
- **Why it matters:** your manual testing becomes graph data automatically —
  the endpoints and parameters you actually exercise get added and flagged
  without leaving Burp.

---

## 9. Graph UI & interaction

**Click a node → detail panel** showing:

- For a `subdomain`: all `has_endpoint` children with method + **status code**
  + content length + title, its resolved IPs, tech stack, certs, and findings.
- For an `ip`: every host on it (shared-infra view), open services from nmap.
- For an `endpoint`: params, status code history, linked functionality, findings.

**Expand-on-click** is how it stays usable at scale: the graph never loads
everything. It starts at root domains; clicking a node lazily fetches its
1-hop neighborhood from the backend.

**Scale mitigations (the hairball problem)**

- Default view = roots only; expand on demand.
- Filter by node type and status (e.g. "flagged only", "hide out-of-scope").
- Cluster shared infra — collapse N subdomains on one IP into a group node.
- Renderer by scale: SVG/Cytoscape ≤ ~500 visible nodes, Sigma.js (WebGL) beyond.

---

## 10. The editor page

A dedicated mode for the manual structure that tools can't give you.

- **Add / edit nodes:** create a `functionality` ("password reset flow",
  "file upload", "GraphQL"), edit any node's status, tags, and notes.
- **Add / edit edges:** manually link an `endpoint` to a `functionality`
  (`part_of`), connect a `finding` to everything it `affects`, draw a
  suspected relationship between hosts.
- **Group functionalities:** select several endpoints/params and attach them
  to one `functionality` node — so you can later view "everything that makes up
  the auth flow" as a subgraph.
- **Bulk triage:** multi-select → set status, tag, or move in/out of scope.

This is what turns the auto-generated graph into *your* map.

---

## 11. Key backend queries

**Expand a node's neighborhood** (the click handler)

Neo4j:
```cypher
MATCH (n {id: $id})-[r]-(m)
WHERE ($types IS NULL OR m.type IN $types)
RETURN n, r, m
LIMIT 500
```

Postgres (edge table):
```sql
SELECT e.*, m.*
FROM edges e
JOIN nodes m ON m.id = CASE WHEN e.from_id = :id THEN e.to_id ELSE e.from_id END
WHERE e.from_id = :id OR e.to_id = :id
LIMIT 500;
```

**Endpoints + status codes for a host** (the detail panel)

Neo4j:
```cypher
MATCH (h:subdomain {id: $id})-[:has_endpoint]->(e:endpoint)
RETURN e.value, e.props.method, e.props.status_code, e.props.content_length
ORDER BY e.props.status_code
```

**Shared-infrastructure view** (hosts behind one IP)

```cypher
MATCH (ip:ip {id: $id})<-[:resolves_to]-(s:subdomain)
RETURN s.value, s.status
```

`LIMIT` + type filters keep every interaction bounded so the UI never tries to
render the entire graph.

---

## 12. Identity & deduplication

The single most important correctness rule: **nodes are keyed by a normalized
canonical value**, and every ingest is an **upsert**.

- Normalize FQDNs (lowercase, strip trailing dot), URLs (scheme/host/path),
  IPs, before building the `id`.
- On ingest: `MERGE` (Neo4j) / `INSERT ... ON CONFLICT DO UPDATE` (Postgres);
  update `last_seen`, union `sources`, merge `props`.
- Result: importing httpx then dnsx then Burp for the same host enriches one
  node instead of creating three.

---

## 13. Tech stack (recommended)

| Layer | Choice | Why |
|---|---|---|
| Backend | **Python + FastAPI** | Fast to build; great for parsing/normalizing tool output |
| Store | **Neo4j** (or Postgres + edge table) | Graph queries are one line of Cypher; relational works until graphs get big/deep |
| Frontend | **React + Cytoscape.js** | Purpose-built graph viz with expand/collapse, filtering, layouts |
| Big-graph renderer | **Sigma.js** (WebGL) | Drop-in when node counts blow past Cytoscape's comfort zone |
| Burp ext | **Kotlin + Montoya API** | Modern Burp extension API; posts JSON to `/ingest` |
| Importers | **Python CLI + folder watcher** | `mapper import <tool> <file>`; auto-ingest new results |

Start with Postgres + an edges table if you'd rather avoid running Neo4j; the
API shape stays identical, so you can swap the store later.

---

## 14. Implementation patterns

These patterns aren't decoration — each one is chosen because it removes a
specific source of future pain in *this* system (swapping the store, adding a
new tool, undoing an edit). Build to these from the start and the open
decisions in §18 stay cheap to change.

### Overarching: ports & adapters (hexagonal architecture)

Keep the **canonical graph model + ingest/dedupe logic as the core**, and treat
everything else as a plug-in adapter around it:

```
                 +---------------------------+
   importers --->|                           |---> Neo4j adapter
   Burp ext  --->|   DOMAIN CORE             |---> Postgres adapter
   CLI       --->|  (nodes, edges, dedupe,   |
   file watch--->|   status rules)           |---> Cytoscape adapter
                 |                           |---> Sigma adapter
                 +---------------------------+
                   ports (interfaces)
```

The core never imports a tool library or a database driver. It depends only on
interfaces (ports); the concrete tools, stores, and renderers are adapters that
implement them. This is what makes "swap Neo4j for Postgres" or "swap Cytoscape
for Sigma" a one-file change instead of a rewrite.

### Pattern-to-component map

| Pattern | Where | Concrete payoff |
|---|---|---|
| **Repository** | Store access (`GraphRepository` with `upsert_node`, `upsert_edge`, `neighbors`, `node_detail`) | The Neo4j-vs-Postgres decision (§18) becomes two interchangeable classes; the rest of the code never knows which is running |
| **Strategy + Registry** | One importer per tool, registered by name | `mapper import <tool>` dispatches dynamically; adding nuclei/amass = drop in a new strategy, zero changes elsewhere |
| **Adapter** | Each importer + the Burp extension | Adapts each tool's idiosyncratic output (nmap XML, httpx JSON, Burp request objects) into the canonical node/edge model |
| **Facade / Service layer** | One `IngestService.ingest(ops)` | CLI, folder watcher, and Burp push all funnel through a single write path — dedupe and validation live in exactly one place |
| **Command** | Every mutation (upsert node, add edge, set status) is a command object | Gives the editor **undo/redo**, an audit log, and lets the Burp ext / CLI reuse the same mutation objects |
| **Identity Map** | Per-import in-memory `canonical_id → node` cache | Prevents re-querying/re-creating the same host 50 times during one import run — the heart of fast dedupe |
| **Value Object** | The normalized canonical key (FQDN/URL/IP) | Equality-by-value makes dedupe correct and keys collision-free; normalization rules live in one immutable type |
| **State machine** | Triage status (`untriaged → in_scope → testing → flagged → confirmed → done`) | Encodes legal transitions in one place; the UI can't put a node in an impossible state |
| **Observer / pub-sub** | Frontend selection + filters; Burp's Montoya HTTP handler | Selecting a node updates the detail panel and highlights edges without tangled callbacks; Burp capture is event-driven by nature |
| **Renderer interface (Strategy)** | `GraphRenderer` over Cytoscape / Sigma | Switch renderer by graph size at runtime (SVG for small, WebGL for huge) behind one interface |
| **Unit of Work** | Wrap a whole import in one transaction | An import either fully lands or fully rolls back — no half-ingested graphs |

### Three rules that keep it maintainable

1. **Program to the ports, not the tools.** Importers depend on the
   `Importer` interface and emit canonical ops; they never write to the DB
   directly. The DB is reached only through `GraphRepository`.
2. **One write path.** All node/edge changes — from importers, the editor, or
   Burp — become `Command` objects handed to `IngestService`. Dedupe,
   validation, and audit happen there and nowhere else.
3. **The domain core stays dependency-free.** No FastAPI, no Neo4j driver, no
   Cytoscape inside the core model. If the core imports a framework, the
   hexagon has leaked.

---

## 15. LLM & agent integration

Coding/recon agents (Claude Code and similar) should be able to read the graph,
reason over it, and write back — add or refine intuitions, create/modify/remove
nodes, link findings — without ever touching the database directly.

The clean way to do this, and the way that fits the architecture, is an **MCP
server** (Model Context Protocol) exposed as *just another adapter* on the same
query/ingest ports the CLI and Burp extension already use. The agent gets a set
of typed tools, not raw DB access — and because every write flows through the
single `IngestService` path (§14), agent edits inherit dedupe, validation, an
audit log, and **undo** (the Command pattern) for free.

### MCP tool surface

Read (cheap, token-aware):

| Tool | Returns |
|---|---|
| `graph_digest()` | Counts by type/status + the flagged and untriaged queues — the agent's entry point |
| `search(query, type?, status?)` | Matching nodes (paged) |
| `get_node(id)` | Node detail + immediate neighbors |
| `get_neighborhood(id, depth, types?)` | A bounded subgraph around a node |
| `find_patterns(kind)` | Pre-baked hunts: `shared_infra`, `untriaged_endpoints`, `orphan_findings`, `dev_hosts` |

Write (every call becomes a reversible `Command`):

| Tool | Effect |
|---|---|
| `add_node` / `update_node` / `remove_node` | Structural edits |
| `add_edge` / `remove_edge` | Link / unlink |
| `add_finding(kind, confidence, affects[])` | Record an **intuition**, suspicion, or confirmed finding |
| `set_status` / `add_note` / `tag` | Triage + annotation |

These map one-to-one onto `GraphRepository` + `IngestService`, so the MCP server
is a thin layer — no new business logic, just a protocol surface.

### Intuitions as first-class, attributed data

Model an intuition as a `finding` with `kind: intuition | suspected | confirmed`,
plus `author` and `confidence`. An agent's hunch ("admin + api share a host —
likely vhost confusion") becomes a low-confidence `intuition` linked by
`affects` edges to the nodes it concerns, and can later be **promoted** to
`suspected`/`confirmed` as you verify it. No new node type needed.

### Provenance & trust (non-negotiable once an LLM can write)

Extend every node/edge/finding with `author_type: human | tool | agent` and a
`confidence` score. This makes it trivial to:

- Visually distinguish "Claude's hunch" from "httpx found this" from "I
  confirmed this" — and filter the graph by author.
- Roll back any agent contribution cleanly (audit log + Command undo).
- Keep token-heavy reasoning out of the core: the agent never receives the
  whole graph, only the digest + scoped neighborhoods + pattern queries.

### Guardrails

Not all writes are equal. Recommended split: the agent may **read, add, and
annotate** freely, but **destructive or scope-changing** operations (remove a
node, delete a confirmed finding, move something out of scope) land in a
**review queue** you approve in the editor. Every agent action is logged with
the reasoning the agent supplied.

### Example loop

1. Claude Code calls `graph_digest()` → sees 40 untriaged endpoints, 3 flagged hosts.
2. Calls `find_patterns("shared_infra")` → notices `api` + `admin` on one IP.
3. Calls `add_finding(kind="intuition", confidence=0.6, affects=[api, admin, ip])`
   with a note explaining the vhost-confusion idea.
4. You open the editor, see the agent-authored intuition, verify it, and
   promote it to `suspected` — or reject it, reverting the command.

---

## 16. Example end-to-end flow

1. `shuffledns` finds `api.example.com` → `subdomain` node, `subdomain_of` edge.
2. `dnsx` resolves it to `203.0.113.10` → `ip` node, `resolves_to` edge.
3. `nmap` on the IP finds 443/nginx → `service` node, `runs_service` edge.
4. `httpx` probes it → `200`, tech `nginx`/`Node.js`, cert `*.example.com`
   → endpoint enriched, `technology` + `certificate` nodes linked.
5. The shared cert links `api` and `admin` → `shares_cert` edges reveal both
   live on `203.0.113.10`. You flag the IP: *"shared host, try vhost confusion."*
6. In Burp you hit `/v2/users?id=` → the extension pushes it → `endpoint` +
   `parameter` nodes; you tag it *suspected IDOR* → `finding` node, `affects` edge.
7. In the editor you create a `functionality` "user management" and attach
   `/v2/users` and its params to it.

---

## 17. Roadmap

| Phase | Scope |
|---|---|
| **0 — Core** | Schema + store + upsert; importers for httpx + dnsx; read-only graph with expand-on-click + detail panel (endpoints, status codes) |
| **1 — Recon coverage** | importers grouped by capability — ports (nmap, naabu), DNS (shuffledns, dnsx), crawl + URL discovery (katana, gau, waybackurls), content/param discovery (ffuf, kiteRunner, x8); search, filters, status workflow |
| **2 — Editor** | Manual nodes/edges, `functionality` grouping, findings, bulk triage |
| **3 — Burp + nuclei** | Burp extension push integration; nuclei findings import |
| **4 — Scale & share** | WebGL renderer, infra clustering, multi-target workspaces, export/share |
| **5 — Agent / MCP** | MCP server exposing read + reversible write tools; intuition/finding authoring with provenance (`author_type`, `confidence`); review queue for agent edits |

MVP = Phase 0 + 1: import your real recon output and explore it as a graph.

---

## 18. Open decisions

- **Store:** Neo4j (native graph queries) vs Postgres + edges (one less moving
  part). Recommend prototyping Phase 0 on Postgres, reassess at Phase 4.
- **Findings as nodes vs props:** nodes are more flexible (one finding → many
  assets) but inflate node count — lean nodes, hidden by default via filter.
- **Local vs server:** start local-first single-user; the API boundary keeps a
  later server mode open.
- **Scope handling:** in/out-of-scope as a node `status`, or as separate scope
  rules evaluated at ingest? (Affects whether out-of-scope assets are stored.)
- **Live sync vs batch:** file-watch auto-import vs explicit `import` runs.
- **Screenshots/response bodies:** store refs + files on disk, not in the graph.
- **Intuition modeling:** reuse `finding` with `kind: intuition` (promotable,
  one node type) vs a separate annotation type. Recommend the former.
- **Agent write permissions:** which MCP mutations an LLM may commit directly
  vs which require human review. Recommend: reads + add + annotate are direct;
  remove, delete-confirmed, and out-of-scope go to a review queue.