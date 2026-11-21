"""IngestService — the single write path (§14, rule 2).

Every node/edge change, whether from an importer, the editor, or the Burp
extension, funnels through here. Dedupe and validation live in exactly one
place. A per-batch identity map prevents re-upserting the same node many
times during one import run (§14, Identity Map).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Iterable, Optional

from .identity import make_id, normalize_host, registrable_domain

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
    utcnow,
)
from .ports import GraphRepository


def _fold(a: NodeOp, b: NodeOp) -> NodeOp:
    """Merge two mentions of the same node within one batch (later wins on
    scalar fields, tags/props accumulate)."""
    return replace(
        a,
        tags=sorted(set(a.tags) | set(b.tags)),
        props={**a.props, **b.props},
        notes=b.notes if b.notes is not None else a.notes,
        status=b.status if b.status is not None else a.status,
        confidence=b.confidence if b.confidence is not None else a.confidence,
    )



@dataclass
class IngestResult:
    nodes: int = 0
    edges: int = 0
    new_nodes: int = 0      # nodes that did not exist before this batch
    skipped: int = 0        # ops dropped because their value was unparseable

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        s = f"{self.nodes} nodes ({self.new_nodes} new), {self.edges} edges"
        return s + (f", {self.skipped} skipped" if self.skipped else "")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class IngestService:
    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo

    def ingest(
        self,
        ops: Iterable[NodeOp | EdgeOp],
        program: str = "default",
        tool: Optional[str] = None,
    ) -> IngestResult:
        """Merge a batch of ops into the graph.

        The batch is folded in memory first (the identity map): every mention
        of a node is *merged* — tags unioned, props layered — so a host seen 50
        times is written once without losing what the later mentions carried.
        It then lands in one transaction: an import either fully applies or
        leaves the graph untouched. ``tool`` records the run in the import log,
        which is what ``new:last`` queries against.
        """
        result = IngestResult()
        started = utcnow()
        nodes: dict[tuple[str, str], NodeOp] = {}
        edges: dict[tuple[str, str, str, str], EdgeOp] = {}

        for op in ops:
            op.program = program   # stamp the workspace onto every op
            try:
                if isinstance(op, NodeOp):
                    key = (make_id(op.type, op.value, program), op.source)
                    nodes[key] = _fold(nodes[key], op) if key in nodes else op
                elif isinstance(op, EdgeOp):
                    ekey = (
                        op.type.value,
                        make_id(op.from_value_type, op.from_value, program),
                        make_id(op.to_value_type, op.to_value, program),
                        op.source,
                    )
                    if ekey in edges:
                        edges[ekey].props.update(op.props)
                    else:
                        edges[ekey] = op
                else:  # pragma: no cover - defensive
                    raise TypeError(f"unsupported op: {type(op)!r}")
            except ValueError:
                # one malformed record (e.g. a non-IP in an ip field) must not
                # abort the whole import
                result.skipped += 1

        self._link_hosts_to_apex(nodes, edges, program)

        # No dangling edges: an edge end nobody emitted as a node gets a bare
        # stub in this batch, so the store never has to look each one up.
        present = {node_id for node_id, _ in nodes}
        for (_, from_id, to_id, source), eop in edges.items():
            for nid, ntype, nvalue in (
                (from_id, eop.from_value_type, eop.from_value),
                (to_id, eop.to_value_type, eop.to_value),
            ):
                if nid not in present:
                    present.add(nid)
                    nodes[(nid, source)] = NodeOp(ntype, nvalue, source=source, program=program)

        with self._repo.transaction():
            seen: set[str] = set()
            for op in nodes.values():
                node = self._repo.upsert_node(op)
                if node.id not in seen:
                    seen.add(node.id)
                    result.nodes += 1
                    if node.first_seen >= started:
                        result.new_nodes += 1
            seen_edges: set[str] = set()
            for eop in edges.values():
                edge = self._repo.upsert_edge(eop, ensure_nodes=False)
                seen_edges.add(edge.id)
            result.edges = len(seen_edges)
            if tool:
                self._repo.record_import(
                    tool, program, started,
                    nodes=result.nodes, edges=result.edges, new_nodes=result.new_nodes,
                )
        return result

    def _link_hosts_to_apex(self, nodes: dict, edges: dict, program: str) -> None:
        """Every host must hang off an apex ``domain`` so it is reachable from
        the roots view. Most tools (httpx, dnsx, katana, gau, …) only name the
        host, so the link is derived here once instead of in each importer.
        Hosts an importer (or an earlier import) already linked are left alone.
        """
        linked = {k[1] for k in edges if k[0] == EdgeType.subdomain_of.value}
        for (node_id, _source), op in list(nodes.items()):
            if op.type != NodeType.subdomain or node_id in linked:
                continue
            host = normalize_host(op.value)
            if "." not in host or _is_ip(host) or ":" in host:
                continue
            if self._repo.has_edge(node_id, EdgeType.subdomain_of):
                linked.add(node_id)
                continue
            apex = registrable_domain(host)
            dom = NodeOp(NodeType.domain, apex, source=op.source, program=program)
            nodes.setdefault((make_id(NodeType.domain, apex, program), op.source), dom)
            edge = EdgeOp(
                EdgeType.subdomain_of, NodeType.subdomain, host,
                NodeType.domain, apex, source=op.source, program=program,
            )
            edges[(edge.type.value, node_id, make_id(NodeType.domain, apex, program), op.source)] = edge
            linked.add(node_id)

    def repair(self) -> dict:
        """Backfill structure that older imports left out: attach every
        un-rooted host to its apex domain. Safe to run repeatedly."""
        linked = 0
        with self._repo.transaction():
            for node in self._repo.unlinked_hosts():
                host = normalize_host(node.value)
                if "." not in host or _is_ip(host) or ":" in host:
                    continue
                apex = registrable_domain(host)
                self._repo.upsert_edge(EdgeOp(
                    EdgeType.subdomain_of, NodeType.subdomain, host,
                    NodeType.domain, apex, source="repair", program=node.program,
                ))
                linked += 1
        return {"hosts_linked": linked}

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
