"""SQLite-backed GraphRepository.

Phase 0 deliberately uses SQLite rather than the Postgres/Neo4j options in
PROPOSAL.md §13/§18: it needs zero setup, which fits the "local-first,
single-user" goal best. Because all store access goes through the
GraphRepository port, swapping in Postgres or Neo4j later is a new adapter
class, not a rewrite. The edge-table shape mirrors the §11 Postgres queries.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from typing import Iterable, Optional

from ...domain.identity import make_id
from ...domain.model import (
    AuthorType,
    Edge,
    EdgeOp,
    EdgeType,
    Node,
    NodeOp,
    NodeType,
    Status,
    merge_node,
    utcnow,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    status      TEXT NOT NULL,
    tags        TEXT NOT NULL DEFAULT '[]',
    notes       TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    sources     TEXT NOT NULL DEFAULT '[]',
    author_type TEXT NOT NULL DEFAULT 'tool',
    confidence  REAL,
    props       TEXT NOT NULL DEFAULT '{}',
    program     TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_nodes_type    ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_nodes_status  ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_nodes_value   ON nodes(value);

CREATE TABLE IF NOT EXISTS edges (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    from_id     TEXT NOT NULL,
    to_id       TEXT NOT NULL,
    sources     TEXT NOT NULL DEFAULT '[]',
    first_seen  TEXT NOT NULL,
    author_type TEXT NOT NULL DEFAULT 'tool',
    props       TEXT NOT NULL DEFAULT '{}',
    program     TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id);
CREATE INDEX IF NOT EXISTS idx_edges_to   ON edges(to_id);
"""


def _locked(fn):
    """Serialize a repository method through the instance lock (RLock allows
    the nested calls, e.g. upsert_node → get_node)."""

    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)

    wrapper.__name__ = fn.__name__
    return wrapper


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


class SqliteGraphRepository:
    def __init__(self, path: str = "rainman.db") -> None:
        # check_same_thread=False + a lock: FastAPI runs sync endpoints in a
        # threadpool, so the connection is shared across threads but every
        # access is serialized through ``self._lock``.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add the program column to pre-existing databases (CREATE TABLE
        IF NOT EXISTS won't alter an existing table)."""
        for table in ("nodes", "edges"):
            cols = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if "program" not in cols:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN program TEXT NOT NULL DEFAULT 'default'"
                )
        # index created after the column exists (works for both new and migrated DBs)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_program ON nodes(program)")

    def close(self) -> None:
        self._conn.close()

    # -- row <-> model -----------------------------------------------------
    @staticmethod
    def _row_to_node(r: sqlite3.Row) -> Node:
        return Node(
            id=r["id"],
            type=NodeType(r["type"]),
            value=r["value"],
            status=Status(r["status"]),
            tags=json.loads(r["tags"]),
            notes=r["notes"],
            first_seen=_parse_dt(r["first_seen"]),
            last_seen=_parse_dt(r["last_seen"]),
            sources=json.loads(r["sources"]),
            author_type=AuthorType(r["author_type"]),
            confidence=r["confidence"],
            props=json.loads(r["props"]),
            program=r["program"],
        )

    @staticmethod
    def _row_to_edge(r: sqlite3.Row) -> Edge:
        return Edge(
            id=r["id"],
            type=EdgeType(r["type"]),
            from_id=r["from_id"],
            to_id=r["to_id"],
            sources=json.loads(r["sources"]),
            first_seen=_parse_dt(r["first_seen"]),
            author_type=AuthorType(r["author_type"]),
            props=json.loads(r["props"]),
            program=r["program"],
        )

    def _write_node(self, n: Node) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO nodes
               (id,type,value,status,tags,notes,first_seen,last_seen,
                sources,author_type,confidence,props,program)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                n.id, n.type.value, n.value, n.status.value,
                json.dumps(n.tags), n.notes, _iso(n.first_seen), _iso(n.last_seen),
                json.dumps(n.sources), n.author_type.value, n.confidence,
                json.dumps(n.props), n.program,
            ),
        )

    # -- GraphRepository port ---------------------------------------------
    @_locked
    def upsert_node(self, op: NodeOp) -> Node:
        node_id = make_id(op.type, op.value, op.program)
        existing = self.get_node(node_id)
        if existing is None:
            node = Node(
                id=node_id,
                type=op.type,
                value=op.value,
                status=op.status or Status.untriaged,
                tags=sorted(set(op.tags)),
                notes=op.notes or "",
                sources=[op.source] if op.source else [],
                author_type=op.author_type,
                confidence=op.confidence,
                props=dict(op.props),
                program=op.program,
            )
        else:
            node = merge_node(existing, op, node_id)
        self._write_node(node)
        self._conn.commit()
        return node

    @_locked
    def upsert_edge(self, op: EdgeOp) -> Edge:
        from_id = make_id(op.from_value_type, op.from_value, op.program)
        to_id = make_id(op.to_value_type, op.to_value, op.program)
        return self._upsert_edge(
            op.type, from_id, to_id, op.source, op.author_type, op.props, op.program
        )

    @_locked
    def link_nodes(
        self,
        from_id: str,
        to_id: str,
        edge_type: EdgeType,
        *,
        source: str = "manual",
        author_type: AuthorType = AuthorType.human,
        props: Optional[dict] = None,
    ) -> Optional[Edge]:
        """Editor/agent edge creation by existing node id. Both endpoints must
        already exist; returns None if either is missing. The edge inherits the
        program of its endpoints."""
        a = self.get_node(from_id)
        b = self.get_node(to_id)
        if a is None or b is None:
            return None
        return self._upsert_edge(
            edge_type, from_id, to_id, source, author_type, props or {}, a.program
        )

    def _upsert_edge(
        self,
        edge_type: EdgeType,
        from_id: str,
        to_id: str,
        source: str,
        author_type: AuthorType,
        props: dict,
        program: str = "default",
    ) -> Edge:
        edge_id = f"edge:{edge_type.value}:{from_id}:{to_id}"
        row = self._conn.execute("SELECT * FROM edges WHERE id=?", (edge_id,)).fetchone()
        if row is None:
            edge = Edge(
                id=edge_id, type=edge_type, from_id=from_id, to_id=to_id,
                sources=[source] if source else [],
                author_type=author_type, props=dict(props), program=program,
            )
        else:
            edge = self._row_to_edge(row)
            edge.sources = sorted(set(edge.sources) | ({source} if source else set()))
            edge.props = {**edge.props, **props}
        self._conn.execute(
            """INSERT OR REPLACE INTO edges
               (id,type,from_id,to_id,sources,first_seen,author_type,props,program)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                edge.id, edge.type.value, edge.from_id, edge.to_id,
                json.dumps(edge.sources), _iso(edge.first_seen),
                edge.author_type.value, json.dumps(edge.props), edge.program,
            ),
        )
        self._conn.commit()
        return edge

    @_locked
    def get_node(self, node_id: str) -> Optional[Node]:
        row = self._conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return self._row_to_node(row) if row else None

    @_locked
    def remove_node(self, node_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        self._conn.execute("DELETE FROM edges WHERE from_id=? OR to_id=?", (node_id, node_id))
        self._conn.commit()
        return cur.rowcount > 0

    @_locked
    def remove_edge(self, edge_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM edges WHERE id=?", (edge_id,))
        self._conn.commit()
        return cur.rowcount > 0

    @_locked
    def update_node(
        self,
        node_id: str,
        *,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        add_tags: Optional[Iterable[str]] = None,
        set_tags: Optional[Iterable[str]] = None,
        props: Optional[dict] = None,
    ) -> Optional[Node]:
        node = self.get_node(node_id)
        if node is None:
            return None
        if status is not None:
            node.status = Status(status)
        if notes is not None:
            node.notes = notes
        if set_tags is not None:          # authoritative replace (enables removal)
            node.tags = sorted(set(set_tags))
        elif add_tags:
            node.tags = sorted(set(node.tags) | set(add_tags))
        if props:
            node.props = {**node.props, **props}
        node.last_seen = utcnow()
        self._write_node(node)
        self._conn.commit()
        return node

    @_locked
    def neighbors(
        self, node_id: str, *, types: Optional[list[str]] = None, limit: int = 500
    ) -> tuple[list[Edge], list[Node]]:
        rows = self._conn.execute(
            "SELECT * FROM edges WHERE from_id=? OR to_id=? LIMIT ?",
            (node_id, node_id, limit),
        ).fetchall()
        edges = [self._row_to_edge(r) for r in rows]
        far_ids = {e.to_id if e.from_id == node_id else e.from_id for e in edges}
        nodes: list[Node] = []
        for fid in far_ids:
            n = self.get_node(fid)
            if n is None:
                continue
            if types and n.type.value not in types:
                continue
            nodes.append(n)
        if types:
            keep = {n.id for n in nodes} | {node_id}
            edges = [e for e in edges if e.from_id in keep and e.to_id in keep]
        return edges, nodes

    @_locked
    def search(
        self,
        query: str,
        *,
        type: Optional[str] = None,
        status: Optional[str] = None,
        program: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Node]:
        # tags are stored as a JSON array string, so a LIKE on the raw text
        # matches a tag substring (good enough for the search box).
        sql = "SELECT * FROM nodes WHERE (value LIKE ? OR notes LIKE ? OR tags LIKE ?)"
        args: list = [f"%{query}%", f"%{query}%", f"%{query}%"]
        if type:
            sql += " AND type=?"
            args.append(type)
        if status:
            sql += " AND status=?"
            args.append(status)
        if program:
            sql += " AND program=?"
            args.append(program)
        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        return [self._row_to_node(r) for r in self._conn.execute(sql, args).fetchall()]

    @_locked
    def roots(self, limit: int = 100, program: Optional[str] = None) -> list[Node]:
        """Entry-point nodes for the graph view: programs + domains, falling
        back to subdomains when no apex/program nodes exist yet."""
        pclause = " AND program=?" if program else ""
        pargs = (program,) if program else ()
        rows = self._conn.execute(
            "SELECT * FROM nodes WHERE type IN ('program','domain')" + pclause
            + " ORDER BY type, value LIMIT ?",
            (*pargs, limit),
        ).fetchall()
        if not rows:
            rows = self._conn.execute(
                "SELECT * FROM nodes WHERE type='subdomain'" + pclause
                + " ORDER BY last_seen DESC LIMIT ?",
                (*pargs, limit),
            ).fetchall()
        return [self._row_to_node(r) for r in rows]

    @_locked
    def programs(self) -> list[dict]:
        """Distinct programs with node counts (for the workspace switcher)."""
        return [
            {"program": r["program"], "nodes": r["c"]}
            for r in self._conn.execute(
                "SELECT program, COUNT(*) c FROM nodes GROUP BY program ORDER BY program"
            )
        ]

    @_locked
    def digest(self, program: Optional[str] = None) -> dict:
        # optional "program=?" predicate appended to each count query
        pc = " AND program=?" if program else ""
        pw = " WHERE program=?" if program else ""
        pa = (program,) if program else ()
        by_type = {
            r["type"]: r["c"]
            for r in self._conn.execute(
                "SELECT type, COUNT(*) c FROM nodes" + pw + " GROUP BY type", pa)
        }
        by_status = {
            r["status"]: r["c"]
            for r in self._conn.execute(
                "SELECT status, COUNT(*) c FROM nodes" + pw + " GROUP BY status", pa)
        }
        flagged = [
            self._row_to_node(r)
            for r in self._conn.execute(
                "SELECT * FROM nodes WHERE status=?" + pc
                + " ORDER BY last_seen DESC LIMIT 50",
                (Status.flagged.value, *pa),
            ).fetchall()
        ]
        untriaged = self._conn.execute(
            "SELECT COUNT(*) c FROM nodes WHERE status=?" + pc,
            (Status.untriaged.value, *pa),
        ).fetchone()["c"]
        total_edges = self._conn.execute(
            "SELECT COUNT(*) c FROM edges" + pw, pa).fetchone()["c"]
        return {
            "nodes_by_type": by_type,
            "nodes_by_status": by_status,
            "total_nodes": sum(by_type.values()),
            "total_edges": total_edges,
            "untriaged": untriaged,
            "flagged": [{"id": n.id, "value": n.value, "type": n.type.value} for n in flagged],
        }
