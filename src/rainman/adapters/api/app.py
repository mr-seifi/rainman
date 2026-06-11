"""FastAPI app — the single reader/writer over HTTP.

Serves the digest, search, node detail, and expand-on-click neighborhood
queries, and accepts writes from importers (``/import/{tool}``), the editor
(``PATCH/DELETE``), and the Burp extension / MCP (``/ingest``). Every write
goes through IngestService so dedupe and validation live in one place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
from ..importers import available, get_importer
from ..store import SqliteGraphRepository
from .serialize import edge_to_dict, node_to_dict


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


class FunctionalityIn(BaseModel):
    name: str
    description: Optional[str] = None
    members: list[str] = []
    author_type: AuthorType = AuthorType.human


class BulkStatusIn(BaseModel):
    ids: list[str]
    status: Optional[Status] = None
    add_tags: list[str] = []


def create_app(db_path: str = "rainman.db") -> FastAPI:
    repo = SqliteGraphRepository(db_path)
    svc = IngestService(repo)
    app = FastAPI(title="rainman", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(_STATIC / "index.html")

    @app.get("/digest")
    def digest():
        return repo.digest()

    @app.get("/roots")
    def roots(limit: int = 100):
        nodes = repo.roots(limit=limit)
        return {"nodes": [node_to_dict(n) for n in nodes]}

    @app.get("/importers")
    def importers():
        return {"available": available()}

    @app.get("/search")
    def search(
        q: str = "",
        type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        nodes = repo.search(q, type=type, status=status, limit=limit, offset=offset)
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
        return {
            "edges": [edge_to_dict(e) for e in edges],
            "nodes": [node_to_dict(x) for x in neighbors],
        }

    @app.post("/import/{tool}")
    def import_tool(tool: str, data: str = Body(..., media_type="text/plain")):
        try:
            importer = get_importer(tool)
        except KeyError as e:
            raise HTTPException(404, str(e))
        result = svc.ingest(importer.parse(data))
        return {"tool": tool, "nodes": result.nodes, "edges": result.edges}

    @app.post("/ingest")
    def ingest(payload: IngestIn):
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
        result = svc.ingest(ops)
        return {"nodes": result.nodes, "edges": result.edges}

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
        )
        return {"node": node_to_dict(node)}

    @app.post("/functionality")
    def add_functionality(payload: FunctionalityIn):
        node = svc.create_functionality(
            payload.name, description=payload.description,
            members=payload.members, author_type=payload.author_type,
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
