"""Canonical graph model: node/edge types, status state machine, and the
plain data objects that flow through the system.

Everything is a typed node with a shared envelope plus a type-specific
``props`` bag, connected by typed edges. See PROPOSAL.md §4–§5.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NodeType(str, Enum):
    program = "program"
    domain = "domain"
    subdomain = "subdomain"
    ip = "ip"
    asn = "asn"
    service = "service"
    endpoint = "endpoint"
    parameter = "parameter"
    technology = "technology"
    certificate = "certificate"
    finding = "finding"
    functionality = "functionality"


class EdgeType(str, Enum):
    subdomain_of = "subdomain_of"
    resolves_to = "resolves_to"
    cname_to = "cname_to"
    announced_by = "announced_by"
    runs_service = "runs_service"
    has_endpoint = "has_endpoint"
    has_param = "has_param"
    uses_tech = "uses_tech"
    shares_cert = "shares_cert"
    affects = "affects"
    part_of = "part_of"


class Status(str, Enum):
    """Triage workflow. Transitions are enforced by ``can_transition``."""

    untriaged = "untriaged"
    in_scope = "in_scope"
    testing = "testing"
    flagged = "flagged"
    confirmed = "confirmed"
    done = "done"
    ignored = "ignored"
    out_of_scope = "out_of_scope"


# Legal forward transitions. Terminal-ish states can always be re-opened to
# in_scope so nothing gets permanently stuck.
_TRANSITIONS: dict[Status, set[Status]] = {
    Status.untriaged: {Status.in_scope, Status.ignored, Status.out_of_scope},
    Status.in_scope: {Status.testing, Status.flagged, Status.ignored, Status.out_of_scope},
    Status.testing: {Status.flagged, Status.confirmed, Status.in_scope, Status.done},
    Status.flagged: {Status.confirmed, Status.testing, Status.done, Status.ignored},
    Status.confirmed: {Status.done, Status.flagged},
    Status.done: {Status.in_scope},
    Status.ignored: {Status.in_scope},
    Status.out_of_scope: {Status.in_scope},
}


def can_transition(src: Status, dst: Status) -> bool:
    if src == dst:
        return True
    return dst in _TRANSITIONS.get(src, set())


class AuthorType(str, Enum):
    human = "human"
    tool = "tool"
    agent = "agent"


@dataclass
class Node:
    id: str
    type: NodeType
    value: str
    status: Status = Status.untriaged
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    sources: list[str] = field(default_factory=list)
    author_type: AuthorType = AuthorType.tool
    confidence: Optional[float] = None
    props: dict[str, Any] = field(default_factory=dict)
    program: str = "default"


@dataclass
class Edge:
    id: str
    type: EdgeType
    from_id: str
    to_id: str
    sources: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=utcnow)
    author_type: AuthorType = AuthorType.tool
    props: dict[str, Any] = field(default_factory=dict)
    program: str = "default"


# ---------------------------------------------------------------------------
# Ingest ops — the canonical, store-agnostic instructions importers emit.
# An importer never touches the DB; it produces NodeOp/EdgeOp values that the
# IngestService merges through the repository (§14, rule 1 & 2).
# ---------------------------------------------------------------------------


@dataclass
class NodeOp:
    type: NodeType
    value: str
    source: str
    status: Optional[Status] = None
    tags: list[str] = field(default_factory=list)
    notes: Optional[str] = None
    author_type: AuthorType = AuthorType.tool
    confidence: Optional[float] = None
    props: dict[str, Any] = field(default_factory=dict)
    program: str = "default"


@dataclass
class EdgeOp:
    type: EdgeType
    from_value_type: NodeType
    from_value: str
    to_value_type: NodeType
    to_value: str
    source: str
    author_type: AuthorType = AuthorType.tool
    props: dict[str, Any] = field(default_factory=dict)
    program: str = "default"


_HISTORY_CAP = 20


def merge_node(existing: Node, op: NodeOp, new_id: str) -> Node:
    """Upsert rule: union sources, refresh last_seen, shallow-merge props.

    Used by the repository's upsert path so the merge policy lives in exactly
    one place regardless of which store backs it.
    """

    sources = sorted(set(existing.sources) | ({op.source} if op.source else set()))
    tags = sorted(set(existing.tags) | set(op.tags))
    props = {**existing.props, **op.props}

    # Keep a short trail when an observed status code flips (403→200, …): a
    # behaviour change is a lead, and last-write-wins would erase it.
    old_code, new_code = existing.props.get("status_code"), op.props.get("status_code")
    if old_code is not None and new_code is not None and old_code != new_code:
        history = list(existing.props.get("status_code_history") or [])
        history.append({"code": old_code, "until": utcnow().isoformat()})
        props["status_code_history"] = history[-_HISTORY_CAP:]

    # An op may only move status along a legal transition; anything else is
    # ignored rather than letting bulk writes bypass the state machine.
    status = existing.status
    if op.status is not None and can_transition(existing.status, op.status):
        status = op.status

    return replace(
        existing,
        last_seen=utcnow(),
        sources=sources,
        tags=tags,
        notes=op.notes if op.notes is not None else existing.notes,
        status=status,
        confidence=op.confidence if op.confidence is not None else existing.confidence,
        props=props,
    )
