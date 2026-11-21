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

    def record_import(
        self, tool: str, program: str, started_at, *, nodes: int, edges: int, new_nodes: int
    ) -> None: ...

    def imports(self, program: Optional[str] = None, limit: int = 20) -> list[dict]: ...


@runtime_checkable
class Importer(Protocol):
    """Adapts one tool's output into canonical ops. Pure: no DB access."""

    name: str

    def parse(self, raw: str) -> Iterable[NodeOp | EdgeOp]: ...
