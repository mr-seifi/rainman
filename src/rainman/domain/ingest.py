"""IngestService — the single write path (§14, rule 2).

Every node/edge change, whether from an importer, the editor, or the Burp
extension, funnels through here. Dedupe and validation live in exactly one
place. A per-batch identity map prevents re-upserting the same node many
times during one import run (§14, Identity Map).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .model import Edge, EdgeOp, Node, NodeOp
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

    def ingest(self, ops: Iterable[NodeOp | EdgeOp]) -> IngestResult:
        result = IngestResult()
        # Identity map scoped to this batch: dedupe identical node values so a
        # host mentioned 50 times in one file is upserted once.
        seen_nodes: dict[tuple[str, str], Node] = {}
        seen_edges: set[str] = set()

        for op in ops:
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
