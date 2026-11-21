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
from contextlib import contextmanager
from typing import Iterable, Iterator, Optional

from ...domain.identity import display_value, make_id, normalize_url
from ...domain.query import Term, parse_when
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

CREATE TABLE IF NOT EXISTS imports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tool       TEXT NOT NULL,
    program    TEXT NOT NULL,
    started_at TEXT NOT NULL,
    nodes      INTEGER NOT NULL DEFAULT 0,
    edges      INTEGER NOT NULL DEFAULT 0,
    new_nodes  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_first_seen ON nodes(first_seen);
"""

# Node fields a query key maps straight onto (everything else is a prop).
_COLUMNS = {
    "type": "type", "status": "status", "program": "program",
    "author": "author_type", "id": "id",
}
_SORT_COLUMNS = {"value", "type", "status", "first_seen", "last_seen", "program", "confidence"}
_DEGREE = "(SELECT COUNT(*) FROM edges WHERE from_id = nodes.id OR to_id = nodes.id)"
_ESC = " ESCAPE '\\'"


def _like(v: str, *, contains: bool = False) -> str:
    """Query value → LIKE pattern: escape LIKE metacharacters, ``*`` → ``%``.
    ``contains`` wraps a wildcard-free value so it matches as a substring."""
    out = v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    if "*" in out:
        return out.replace("*", "%")
    return f"%{out}%" if contains else out


def _number(v: str) -> float:
    try:
        return float(v)
    except ValueError:
        raise ValueError(f"expected a number, got {v!r}")



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
        self._tx_depth = 0
        # WAL: readers aren't blocked by a long import; no-op for :memory:.
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
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
        # Endpoints used to keep whichever raw URL arrived first; store the
        # canonical host/path instead and move the scheme into props.
        for r in self._conn.execute(
            "SELECT id, value, props FROM nodes WHERE type='endpoint' AND value LIKE '%://%'"
        ).fetchall():
            props = json.loads(r["props"])
            props.setdefault("scheme", r["value"].split("://", 1)[0].lower())
            self._conn.execute(
                "UPDATE nodes SET value=?, props=? WHERE id=?",
                (normalize_url(r["value"]), json.dumps(props), r["id"]),
            )
        # index created after the column exists (works for both new and migrated DBs)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_program ON nodes(program)")

    def close(self) -> None:
        self._conn.close()

    # -- unit of work ------------------------------------------------------
    def _commit(self) -> None:
        """Commit unless a ``transaction()`` block is open (it commits once)."""
        if self._tx_depth == 0:
            self._conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """All writes in the block land together or roll back together. Holds
        the instance lock, so the batch is also isolated from other threads."""
        with self._lock:
            self._tx_depth += 1
            try:
                yield
            except BaseException:
                self._tx_depth -= 1
                if self._tx_depth == 0:
                    self._conn.rollback()
                raise
            else:
                self._tx_depth -= 1
                if self._tx_depth == 0:
                    self._conn.commit()

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
                value=display_value(op.type, op.value),
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
        self._commit()
        return node

    @_locked
    def upsert_edge(self, op: EdgeOp, *, ensure_nodes: bool = True) -> Edge:
        from_id = make_id(op.from_value_type, op.from_value, op.program)
        to_id = make_id(op.to_value_type, op.to_value, op.program)
        # No dangling edges: an edge to a node nobody emitted creates a bare
        # stub, so the far end is always visible and expandable. A caller that
        # has already guaranteed both ends (IngestService) skips the lookups.
        for nid, ntype, nvalue in (
            (from_id, op.from_value_type, op.from_value),
            (to_id, op.to_value_type, op.to_value),
        ) if ensure_nodes else ():
            if self._conn.execute("SELECT 1 FROM nodes WHERE id=?", (nid,)).fetchone() is None:
                self.upsert_node(NodeOp(
                    ntype, nvalue, source=op.source,
                    author_type=op.author_type, program=op.program,
                ))
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
        self._commit()
        return edge

    @_locked
    def get_node(self, node_id: str) -> Optional[Node]:
        row = self._conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return self._row_to_node(row) if row else None

    @_locked
    def remove_node(self, node_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        self._conn.execute("DELETE FROM edges WHERE from_id=? OR to_id=?", (node_id, node_id))
        self._commit()
        return cur.rowcount > 0

    @_locked
    def remove_edge(self, edge_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM edges WHERE id=?", (edge_id,))
        self._commit()
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
        self._commit()
        return node

    @_locked
    def neighbors(
        self, node_id: str, *, types: Optional[list[str]] = None, limit: int = 500
    ) -> tuple[list[Edge], list[Node]]:
        far = "CASE WHEN e.from_id = ? THEN e.to_id ELSE e.from_id END"
        sql = (
            f"SELECT e.* FROM edges e JOIN nodes m ON m.id = {far} "
            "WHERE (e.from_id = ? OR e.to_id = ?)"
        )
        args: list = [node_id, node_id, node_id]
        if types:
            sql += f" AND m.type IN ({','.join('?' * len(types))})"
            args.extend(types)
        # deterministic order: structure first, then the far node's name
        sql += " ORDER BY e.type, m.value LIMIT ?"
        args.append(limit)
        edges = [self._row_to_edge(r) for r in self._conn.execute(sql, args).fetchall()]
        far_ids = list(dict.fromkeys(
            e.to_id if e.from_id == node_id else e.from_id for e in edges
        ))
        nodes: list[Node] = []
        for i in range(0, len(far_ids), 500):
            chunk = far_ids[i:i + 500]
            rows = self._conn.execute(
                f"SELECT * FROM nodes WHERE id IN ({','.join('?' * len(chunk))})", chunk
            ).fetchall()
            nodes.extend(self._row_to_node(r) for r in rows)
        order = {nid: i for i, nid in enumerate(far_ids)}
        nodes.sort(key=lambda n: order[n.id])
        return edges, nodes

    @_locked
    def degree(self, node_id: str) -> int:
        """Total edges touching a node — lets callers tell a truncated
        neighborhood from a complete one."""
        return self._conn.execute(
            "SELECT COUNT(*) c FROM edges WHERE from_id=? OR to_id=?", (node_id, node_id)
        ).fetchone()["c"]

    @_locked
    def has_edge(self, from_id: str, edge_type: EdgeType) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM edges WHERE from_id=? AND type=? LIMIT 1",
            (from_id, EdgeType(edge_type).value),
        ).fetchone() is not None

    @_locked
    def unlinked_hosts(self) -> list[Node]:
        rows = self._conn.execute(
            "SELECT * FROM nodes WHERE type='subdomain' AND NOT EXISTS ("
            "SELECT 1 FROM edges e WHERE e.from_id = nodes.id AND e.type='subdomain_of')"
        ).fetchall()
        return [self._row_to_node(r) for r in rows]

    # -- hunter query ------------------------------------------------------
    def _since(self, value: str, program: Optional[str]) -> Optional[str]:
        """Resolve a ``new:``/``seen:``/``stale:`` value to an ISO timestamp.
        ``last`` means "when the most recent import started"."""
        if value.lower() == "last":
            sql, args = "SELECT started_at FROM imports", ()
            if program:
                sql, args = sql + " WHERE program=?", (program,)
            row = self._conn.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()
            return row["started_at"] if row else None
        when = parse_when(value)
        if when is None:
            raise ValueError(f"bad time {value!r}: use 30m, 24h, 7d, 2w, 'last' or an ISO date")
        return _iso(when)

    def _compile_term(self, t: Term, program: Optional[str]) -> tuple[str, list]:
        key, parts, args = t.key, [], []

        def numeric(expr: str, pre: tuple = ()) -> None:
            for v in t.values:
                parts.append(f"{expr} {t.op} ?")
                args.extend([*pre, _number(v)])

        for v in ([] if key in ("links", "confidence") else t.values):
            if key is None:
                pat = _like(v, contains=True)
                parts.append(f"(value LIKE ?{_ESC} OR notes LIKE ?{_ESC} OR tags LIKE ?{_ESC})")
                args.extend([pat, pat, pat])
            elif key in _COLUMNS:
                parts.append(f"{_COLUMNS[key]} LIKE ?{_ESC}")
                args.append(_like(v))
            elif key in ("value", "notes"):
                parts.append(f"{key} LIKE ?{_ESC}")
                args.append(_like(v, contains=True))
            elif key in ("tag", "source"):
                col = "tags" if key == "tag" else "sources"
                parts.append(
                    f"EXISTS (SELECT 1 FROM json_each(nodes.{col}) j WHERE j.value LIKE ?{_ESC})"
                )
                args.append(_like(v))
            elif key == "host":
                # the host itself, plus everything under it (endpoints, params)
                pat = _like(v)
                parts.append(
                    f"(value LIKE ?{_ESC} OR value LIKE ?{_ESC} OR value LIKE ?{_ESC})"
                )
                args.extend([pat, pat + "/%", pat + ":%"])
            elif key == "tech":
                # on the host directly, or on the host an endpoint belongs to
                parts.append(
                    "(EXISTS (SELECT 1 FROM edges e JOIN nodes t ON t.id = e.to_id"
                    f" WHERE e.type='uses_tech' AND e.from_id = nodes.id AND t.value LIKE ?{_ESC})"
                    " OR EXISTS (SELECT 1 FROM edges h JOIN edges e ON e.from_id = h.from_id"
                    " AND e.type='uses_tech' JOIN nodes t ON t.id = e.to_id"
                    f" WHERE h.type='has_endpoint' AND h.to_id = nodes.id AND t.value LIKE ?{_ESC}))"
                )
                pat = _like(v, contains=True)
                args.extend([pat, pat])
            elif key in ("new", "seen", "stale"):
                since = self._since(v, program)
                if since is None:          # new:last before any import → nothing
                    parts.append("0")
                else:
                    col, op = {"new": ("first_seen", ">="), "seen": ("last_seen", ">="),
                               "stale": ("last_seen", "<")}[key]
                    parts.append(f"{col} {op} ?")
                    args.append(since)
            elif key == "has":
                if v == "notes":
                    parts.append("notes != ''")
                elif v in ("tags", "tag"):
                    parts.append("tags != '[]'")
                else:
                    parts.append("json_type(props, ?) IS NOT NULL")
                    args.append(f'$."{v}"')
            elif t.op != "=":
                parts.append(f"json_extract(props, ?) {t.op} ?")
                args.extend([f'$."{key}"', _number(v)])
            else:
                # JSON booleans surface as 1/0
                v = {"true": "1", "false": "0"}.get(v.lower(), v)
                parts.append(f"CAST(json_extract(props, ?) AS TEXT) LIKE ?{_ESC}")
                args.extend([f'$."{key}"', _like(v)])

        if key == "links":
            numeric(_DEGREE)
        elif key == "confidence":
            numeric("confidence")

        sql = "(" + " OR ".join(parts) + ")"
        if t.negate:
            sql = f"NOT COALESCE({sql}, 0)"
        return sql, args

    @_locked
    def query(
        self,
        terms: list[Term],
        *,
        program: Optional[str] = None,
        sort: Optional[str] = None,
        desc: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Node], int]:
        where, args = ["1"], []
        if program:
            where.append("program = ?")
            args.append(program)
        for t in terms:
            if '"' in (t.key or ""):
                raise ValueError(f"bad key {t.key!r}")
            sql, a = self._compile_term(t, program)
            where.append(sql)
            args.extend(a)
        clause = " AND ".join(where)
        total = self._conn.execute(
            f"SELECT COUNT(*) c FROM nodes WHERE {clause}", args
        ).fetchone()["c"]

        direction = "DESC" if desc else "ASC"
        order_args: list = []
        if not sort:
            order = f"last_seen {direction}"
        elif sort in _SORT_COLUMNS:
            order = f"{sort} {direction}"
        elif sort == "links":
            order = f"{_DEGREE} {direction}"
        else:
            if '"' in sort:
                raise ValueError(f"bad sort key {sort!r}")
            # rows without the prop go last in either direction, so sorting by
            # size or status code never opens on a page of blanks
            order = f"json_extract(props, ?) IS NULL, json_extract(props, ?) {direction}"
            path = f'$."{sort}"'
            order_args.extend([path, path])
        rows = self._conn.execute(
            f"SELECT * FROM nodes WHERE {clause} ORDER BY {order}, id LIMIT ? OFFSET ?",
            [*args, *order_args, limit, offset],
        ).fetchall()
        return [self._row_to_node(r) for r in rows], total

    # -- import log --------------------------------------------------------
    @_locked
    def record_import(
        self, tool: str, program: str, started_at: datetime, *,
        nodes: int, edges: int, new_nodes: int,
    ) -> None:
        self._conn.execute(
            "INSERT INTO imports (tool, program, started_at, nodes, edges, new_nodes)"
            " VALUES (?,?,?,?,?,?)",
            (tool, program, _iso(started_at), nodes, edges, new_nodes),
        )
        self._commit()

    @_locked
    def imports(self, program: Optional[str] = None, limit: int = 20) -> list[dict]:
        sql, args = "SELECT * FROM imports", []
        if program:
            sql += " WHERE program=?"
            args.append(program)
        rows = self._conn.execute(sql + " ORDER BY id DESC LIMIT ?", [*args, limit]).fetchall()
        return [dict(r) for r in rows]

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
