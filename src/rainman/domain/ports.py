"""Ports — the interfaces the core depends on. Adapters implement them.

Programming to these (not to a concrete DB or tool) is what makes the
Neo4j-vs-Postgres decision and "add a new tool" a localized change (§14).
"""

from __future__ import annotations

from typing import ContextManager, Iterable, Optional, Protocol, runtime_checkable

from .model import Edge, EdgeOp, Node, NodeOp


@runtime_checkable
class GraphRepository(Protocol):
    """Store access port. Implementations own dedupe at the persistence layer;
    the merge *policy* still comes from ``model.merge_node``.
    """

    def upsert_node(self, op: NodeOp) -> Node: ...

    def upsert_edge(self, op: EdgeOp, *, ensure_nodes: bool = True) -> Edge: ...

    def link_nodes(self, from_id: str, to_id: str, edge_type, **kwargs): ...

    def get_node(self, node_id: str) -> Optional[Node]: ...

    def remove_node(self, node_id: str) -> bool: ...

    def remove_edge(self, edge_id: str) -> bool: ...

    def update_node(
        self,
        node_id: str,
        *,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        add_tags: Optional[Iterable[str]] = None,
        props: Optional[dict] = None,
    ) -> Optional[Node]: ...

    def neighbors(
        self, node_id: str, *, types: Optional[list[str]] = None, limit: int = 500
    ) -> tuple[list[Edge], list[Node]]:
        """1-hop neighborhood: the edges touching ``node_id`` and the nodes on
        their far ends (the expand-on-click query)."""
        ...

    def search(
        self,
        query: str,
        *,
        type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Node]: ...

    def roots(self, limit: int = 100) -> list[Node]:
        """Entry-point nodes the graph view starts from (programs/domains)."""
        ...

    def digest(self) -> dict:
        """Counts by type/status + flagged/untriaged queues."""
        ...

    def transaction(self) -> ContextManager[None]:
        """Unit of work: writes inside the block commit together or not at all."""
        ...

    def has_edge(self, from_id: str, edge_type) -> bool:
        """Whether ``from_id`` already has an outgoing edge of this type."""
        ...

    def unlinked_hosts(self) -> list[Node]:
        """Subdomain nodes with no ``subdomain_of`` edge (for ``repair``)."""
        ...

    def query(
        self,
        terms: list,
        *,
        program: Optional[str] = None,
        sort: Optional[str] = None,
        desc: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Node], int]:
        """Run a parsed hunter query (``domain.query``); returns the page of
        nodes and the total match count."""
        ...

    def count(self, terms: list, *, program: Optional[str] = None) -> int:
        """Number of nodes a parsed query matches."""
        ...

    def record_import(
        self, tool: str, program: str, started_at, *, nodes: int, edges: int, new_nodes: int
    ) -> None: ...

    def imports(self, program: Optional[str] = None, limit: int = 20) -> list[dict]: ...

    # -- graph navigation (used by the agent surface) ----------------------
    def find_by_value(
        self, values: Iterable[str], program: Optional[str] = None, limit: int = 20
    ) -> list[Node]:
        """Nodes whose value equals any of ``values``, ignoring case."""
        ...

    def related(
        self,
        ids: Iterable[str],
        *,
        edge_types: Optional[list[str]] = None,
        direction: Optional[str] = None,
        node_types: Optional[list[str]] = None,
        terms: Optional[list] = None,
        program: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[tuple[str, str, Edge, Node]], int]:
        """One filtered hop out of ``ids``: ``(origin_id, direction, edge,
        far_node)`` rows plus the total match count."""
        ...

    def edge_summary(self, node_id: str) -> list[dict]:
        """Neighbour counts per (edge type, direction, far node type)."""
        ...

    def adjacency(self, ids: Iterable[str]) -> list[tuple[str, str, str, str, str]]:
        """``(origin, far, edge_type, direction, far_node_type)`` per edge."""
        ...

    def facet(
        self, terms: list, by: str, *, program: Optional[str] = None, limit: int = 30
    ) -> tuple[list[tuple[object, int]], int]:
        """Group a query's matches by a field/tag/prop; returns the groups and
        the total match count."""
        ...

    def schema(self, program: Optional[str] = None) -> list[dict]:
        """Observed (from type, edge type, to type) triples with counts."""
        ...


@runtime_checkable
class Importer(Protocol):
    """Adapts one tool's output into canonical ops. Pure: no DB access."""

    name: str

    def parse(self, raw: str) -> Iterable[NodeOp | EdgeOp]: ...
