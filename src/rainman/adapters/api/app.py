"""FastAPI app — the single reader/writer over HTTP.

Serves the digest, search, node detail, and expand-on-click neighborhood
queries, and accepts writes from importers (``/import/{tool}``), the editor
(``PATCH/DELETE``), and the Burp extension / MCP (``/ingest``). Every write
goes through IngestService so dedupe and validation live in one place.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

_STATIC = Path(__file__).parent / "static"

from ...domain.ingest import IngestService
from ...domain.model import (
    AuthorType,
    EdgeOp,
    EdgeType,
    NodeOp,
    NodeType,
    Status,
    can_transition,
)
from ..agent import AgentTools, McpServer
from ..importers import available, get_importer
from ..store import SqliteGraphRepository
from ...domain.query import LEADS, parse_query
from .serialize import edge_to_dict, export_value, node_to_dict

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class NodeOpIn(BaseModel):
    type: NodeType
    value: str
    source: str = "manual"
    status: Optional[Status] = None
    tags: list[str] = []
    notes: Optional[str] = None
    author_type: AuthorType = AuthorType.human
    confidence: Optional[float] = None
    props: dict = {}


class EdgeOpIn(BaseModel):
    type: EdgeType
    from_type: NodeType
    from_value: str
    to_type: NodeType
    to_value: str
    source: str = "manual"
    author_type: AuthorType = AuthorType.human
    props: dict = {}


class IngestIn(BaseModel):
    nodes: list[NodeOpIn] = []
    edges: list[EdgeOpIn] = []


class NodePatch(BaseModel):
    status: Optional[Status] = None
    notes: Optional[str] = None
    add_tags: list[str] = []
    set_tags: Optional[list[str]] = None
    props: dict = {}


class EdgeIn(BaseModel):
    type: EdgeType
    from_id: str
    to_id: str
    props: dict = {}
    author_type: AuthorType = AuthorType.human


class FindingIn(BaseModel):
    title: str
    kind: str = "suspected"
    severity: Optional[str] = None
    vuln_class: Optional[str] = None
    confidence: Optional[float] = None
    note: Optional[str] = None
    affects: list[str] = []
    author_type: AuthorType = AuthorType.human
    program: str = "default"


class FunctionalityIn(BaseModel):
    name: str
    description: Optional[str] = None
    members: list[str] = []
    author_type: AuthorType = AuthorType.human
    program: str = "default"


class BulkStatusIn(BaseModel):
    ids: list[str]
    status: Optional[Status] = None
    add_tags: list[str] = []


def create_app(db_path: str = "rainman.db", *, agent_read_only: bool = False) -> FastAPI:
    repo = SqliteGraphRepository(db_path)
    svc = IngestService(repo)
    mcp = McpServer(AgentTools(repo, read_only=agent_read_only))
    app = FastAPI(title="rainman", version="0.1.0")

    # The graph holds recon data and findings and the server has no login, so
    # the browser must not be usable as a bridge to it. No CORS headers are
    # sent (other sites can't read responses), and state-changing requests
    # that a browser marks as coming from another origin are refused — which
    # stops a web page from blind-POSTing to localhost. Non-browser clients
    # (curl, the CLI, a Burp extension) send no Origin and are unaffected.
    @app.middleware("http")
    async def same_origin_writes(request: Request, call_next):
        if request.method not in _SAFE_METHODS:
            origin = request.headers.get("origin")
            cross = request.headers.get("sec-fetch-site") == "cross-site"
            if origin and origin != "null":
                cross = cross or urlsplit(origin).netloc != request.headers.get("host")
            elif origin == "null":
                cross = True
            if cross:
                return JSONResponse({"detail": "cross-origin write refused"}, status_code=403)
        return await call_next(request)

    app.mount("/static", StaticFiles(directory=_STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(_STATIC / "index.html")

    @app.get("/digest")
    def digest(program: Optional[str] = None):
        return repo.digest(program=program)

    @app.get("/programs")
    def programs():
        return {"programs": repo.programs()}

    @app.get("/roots")
    def roots(limit: int = 100, program: Optional[str] = None):
        nodes = repo.roots(limit=limit, program=program)
        return {"nodes": [node_to_dict(n) for n in nodes]}

    @app.get("/importers")
    def importers():
        return {"available": available()}

    @app.get("/search")
    def search(
        q: str = "",
        type: Optional[str] = None,
        status: Optional[str] = None,
        program: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        nodes = repo.search(q, type=type, status=status, program=program, limit=limit, offset=offset)
        return {"nodes": [node_to_dict(n) for n in nodes]}

    @app.get("/node")
    def node(id: str = Query(...)):
        n = repo.get_node(id)
        if n is None:
            raise HTTPException(404, f"no node {id!r}")
        edges, neighbors = repo.neighbors(id)
        return {
            "node": node_to_dict(n),
            "edges": [edge_to_dict(e) for e in edges],
            "neighbors": [node_to_dict(x) for x in neighbors],
        }

    @app.get("/neighborhood")
    def neighborhood(
        id: str = Query(...),
        types: Optional[str] = None,
        limit: int = 500,
    ):
        if repo.get_node(id) is None:
            raise HTTPException(404, f"no node {id!r}")
        type_list = [t for t in types.split(",") if t] if types else None
        edges, neighbors = repo.neighbors(id, types=type_list, limit=limit)
        total = repo.degree(id)
        return {
            "edges": [edge_to_dict(e) for e in edges],
            "nodes": [node_to_dict(x) for x in neighbors],
            # lets the UI say "showing 500 of 4,210" instead of silently cutting
            "total": total,
            "truncated": not type_list and len(edges) < total,
        }

    @app.get("/nodes")
    def nodes(
        q: str = "",
        program: Optional[str] = None,
        sort: Optional[str] = None,
        order: str = "desc",
        limit: int = Query(100, ge=1, le=100000),
        offset: int = Query(0, ge=0),
        format: str = "json",
    ):
        """The hunter query endpoint (see ``domain/query.py`` for the syntax).
        ``format=txt|csv|jsonl`` exports the matches for piping into tools."""
        try:
            found, total = repo.query(
                parse_query(q), program=program, sort=sort,
                desc=order != "asc", limit=limit, offset=offset,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        if format == "txt":
            return PlainTextResponse("".join(export_value(n) + "\n" for n in found))
        if format == "jsonl":
            return PlainTextResponse(
                "".join(json.dumps(node_to_dict(n)) + "\n" for n in found),
                media_type="application/x-ndjson",
            )
        if format == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["type", "value", "url", "status", "status_code", "content_length",
                        "title", "tags", "sources", "first_seen", "last_seen", "notes"])
            for n in found:
                w.writerow([
                    n.type.value, n.value, export_value(n), n.status.value,
                    n.props.get("status_code", ""), n.props.get("content_length", ""),
                    n.props.get("title", ""), " ".join(n.tags), " ".join(n.sources),
                    n.first_seen.isoformat(), n.last_seen.isoformat(), n.notes,
                ])
            return PlainTextResponse(buf.getvalue(), media_type="text/csv")
        return {"nodes": [node_to_dict(n) for n in found], "total": total}

    @app.get("/leads")
    def leads(program: Optional[str] = None):
        """Pre-baked hunts with live counts — where to look next."""
        out = []
        for lead in LEADS:
            total = repo.count(parse_query(lead["query"]), program=program)
            out.append({**lead, "count": total})
        return {"leads": out}

    @app.get("/imports")
    def imports(program: Optional[str] = None, limit: int = 20):
        return {"imports": repo.imports(program=program, limit=limit)}

    # -- agent surface ------------------------------------------------------
    # MCP over HTTP (stateless): one JSON-RPC message or batch per POST. The
    # same tools are on stdio via `rainman mcp`. Covered by the same-origin
    # write guard above, so a web page cannot drive it.
    @app.post("/mcp", include_in_schema=False)
    async def mcp_endpoint(request: Request):
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "invalid JSON"}}, status_code=400)
        from starlette.concurrency import run_in_threadpool
        reply = await run_in_threadpool(mcp.handle_payload, payload)
        if reply is None:
            return Response(status_code=202)
        return JSONResponse(reply)

    @app.get("/mcp", include_in_schema=False)
    def mcp_no_stream():
        # no server-initiated messages, so there is no SSE stream to open
        return Response(status_code=405, headers={"Allow": "POST"})

    @app.post("/repair")
    def repair():
        return svc.repair()

    @app.post("/import/{tool}")
    def import_tool(
        tool: str,
        data: str = Body(..., media_type="text/plain"),
        program: str = "default",
    ):
        try:
            importer = get_importer(tool)
        except KeyError as e:
            raise HTTPException(404, str(e))
        try:
            result = svc.ingest(importer.parse(data), program=program, tool=tool)
        except Exception as e:  # malformed tool output — nothing was written
            raise HTTPException(400, f"could not parse {tool} output: {e}")
        return {
            "tool": tool, "program": program, "nodes": result.nodes,
            "edges": result.edges, "new_nodes": result.new_nodes, "skipped": result.skipped,
        }

    @app.post("/ingest")
    def ingest(payload: IngestIn, program: str = "default"):
        ops: list = []
        for n in payload.nodes:
            ops.append(NodeOp(
                type=n.type, value=n.value, source=n.source, status=n.status,
                tags=n.tags, notes=n.notes, author_type=n.author_type,
                confidence=n.confidence, props=n.props,
            ))
        for e in payload.edges:
            ops.append(EdgeOp(
                type=e.type, from_value_type=e.from_type, from_value=e.from_value,
                to_value_type=e.to_type, to_value=e.to_value, source=e.source,
                author_type=e.author_type, props=e.props,
            ))
        result = svc.ingest(ops, program=program)
        return {"nodes": result.nodes, "edges": result.edges, "new_nodes": result.new_nodes}

    @app.patch("/node")
    def patch_node(id: str = Query(...), patch: NodePatch = Body(...)):
        current = repo.get_node(id)
        if current is None:
            raise HTTPException(404, f"no node {id!r}")
        if patch.status is not None and not can_transition(current.status, patch.status):
            raise HTTPException(
                409, f"illegal transition {current.status.value} → {patch.status.value}"
            )
        updated = repo.update_node(
            id,
            status=patch.status.value if patch.status else None,
            notes=patch.notes,
            add_tags=patch.add_tags or None,
            set_tags=patch.set_tags,
            props=patch.props or None,
        )
        return {"node": node_to_dict(updated)}

    @app.delete("/node")
    def delete_node(id: str = Query(...)):
        if not repo.remove_node(id):
            raise HTTPException(404, f"no node {id!r}")
        return {"removed": id}

    # -- editor (§10) -----------------------------------------------------
    @app.post("/edge")
    def add_edge(payload: EdgeIn):
        edge = repo.link_nodes(
            payload.from_id, payload.to_id, payload.type,
            author_type=payload.author_type, props=payload.props,
        )
        if edge is None:
            raise HTTPException(404, "both from_id and to_id must already exist")
        return {"edge": edge_to_dict(edge)}

    @app.delete("/edge")
    def delete_edge(id: str = Query(...)):
        if not repo.remove_edge(id):
            raise HTTPException(404, f"no edge {id!r}")
        return {"removed": id}

    @app.post("/finding")
    def add_finding(payload: FindingIn):
        node = svc.add_finding(
            payload.title, kind=payload.kind, severity=payload.severity,
            vuln_class=payload.vuln_class, confidence=payload.confidence,
            note=payload.note, affects=payload.affects, author_type=payload.author_type,
            program=payload.program,
        )
        return {"node": node_to_dict(node)}

    @app.post("/functionality")
    def add_functionality(payload: FunctionalityIn):
        node = svc.create_functionality(
            payload.name, description=payload.description,
            members=payload.members, author_type=payload.author_type,
            program=payload.program,
        )
        return {"node": node_to_dict(node)}

    @app.post("/bulk/status")
    def bulk_status(payload: BulkStatusIn):
        return svc.bulk_set_status(
            payload.ids,
            payload.status.value if payload.status else None,
            add_tags=payload.add_tags,
        )

    return app
