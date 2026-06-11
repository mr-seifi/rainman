"""IngestService — the single write path (§14, rule 2).

Every node/edge change, whether from an importer, the editor, or the Burp
extension, funnels through here. Dedupe and validation live in exactly one
place. A per-batch identity map prevents re-upserting the same node many
times during one import run (§14, Identity Map).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .model import (
    AuthorType,
    Edge,
    EdgeOp,
    EdgeType,
    Node,
    NodeOp,
    NodeType,
    Status,
    can_transition,
)
from .ports import GraphRepository


@dataclass
class IngestResult:
    nodes: int = 0
    edges: int = 0

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.nodes} nodes, {self.edges} edges"


class IngestService:
    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo

    def ingest(self, ops: Iterable[NodeOp | EdgeOp], program: str = "default") -> IngestResult:
        result = IngestResult()
        # Identity map scoped to this batch: dedupe identical node values so a
        # host mentioned 50 times in one file is upserted once.
        seen_nodes: dict[tuple[str, str], Node] = {}
        seen_edges: set[str] = set()

        for op in ops:
            op.program = program   # stamp the workspace onto every op
            if isinstance(op, NodeOp):
                key = (op.type.value, op.value)
                if key in seen_nodes:
                    continue
                seen_nodes[key] = self._repo.upsert_node(op)
                result.nodes += 1
            elif isinstance(op, EdgeOp):
                edge = self._repo.upsert_edge(op)
                if edge.id not in seen_edges:
                    seen_edges.add(edge.id)
                    result.edges += 1
            else:  # pragma: no cover - defensive
                raise TypeError(f"unsupported op: {type(op)!r}")
        return result

    # Convenience single-op writers used by the API/editor and (later) MCP.
    def upsert_node(self, op: NodeOp) -> Node:
        return self._repo.upsert_node(op)

    def upsert_edge(self, op: EdgeOp) -> Edge:
        return self._repo.upsert_edge(op)

    # -- Editor / agent operations (§10, §15) -----------------------------
    # Higher-level edits expressed once here so the API, CLI, and the future
    # MCP server reuse them instead of re-implementing the structure.

    def add_finding(
        self,
        title: str,
        *,
        kind: str = "suspected",
        severity: Optional[str] = None,
        vuln_class: Optional[str] = None,
        confidence: Optional[float] = None,
        note: Optional[str] = None,
        affects: Iterable[str] = (),
        author_type: AuthorType = AuthorType.human,
        program: str = "default",
    ) -> Node:
        """Create a finding/intuition and link it to the nodes it affects.

        ``kind`` is intuition | suspected | confirmed (§15): an intuition is
        just a low-confidence finding that can later be promoted.
        """
        props = {"kind": kind, "severity": severity, "vuln_class": vuln_class}
        props = {k: v for k, v in props.items() if v is not None}
        node = self._repo.upsert_node(NodeOp(
            type=NodeType.finding, value=title, source="manual", notes=note,
            author_type=author_type, confidence=confidence, props=props, program=program,
        ))
        for target in affects:
            self._repo.link_nodes(
                node.id, target, EdgeType.affects, author_type=author_type
            )
        return node

    def create_functionality(
        self,
        name: str,
        *,
        description: Optional[str] = None,
        members: Iterable[str] = (),
        author_type: AuthorType = AuthorType.human,
        program: str = "default",
    ) -> Node:
        """Create a user-defined functionality and attach members (endpoints/
        params) to it via ``part_of`` edges (member → functionality)."""
        node = self._repo.upsert_node(NodeOp(
            type=NodeType.functionality, value=name, source="manual",
            notes=description, author_type=author_type, props={"name": name}, program=program,
        ))
        for member in members:
            self._repo.link_nodes(
                member, node.id, EdgeType.part_of, author_type=author_type
            )
        return node

    def bulk_set_status(
        self,
        ids: Iterable[str],
        status: Optional[str] = None,
        *,
        add_tags: Iterable[str] = (),
    ) -> dict:
        """Triage many nodes at once. With ``status`` it transition-checks each
        node (skipping illegal/missing); without it, just applies ``add_tags``.
        One bad id never fails the whole batch."""
        target = Status(status) if status else None
        add_tags = list(add_tags)
        updated, skipped = [], []
        for node_id in ids:
            node = self._repo.get_node(node_id)
            if node is None or (target and not can_transition(node.status, target)):
                skipped.append(node_id)
                continue
            self._repo.update_node(
                node_id, status=status, add_tags=add_tags or None
            )
            updated.append(node_id)
        return {"updated": updated, "skipped": skipped}
