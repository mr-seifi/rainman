"""Node/Edge → JSON-able dicts. Kept out of the domain core so the model
stays serialization-framework-free."""

from __future__ import annotations

from ...domain.model import Edge, Node


def node_to_dict(n: Node) -> dict:
    return {
        "id": n.id,
        "type": n.type.value,
        "value": n.value,
        "status": n.status.value,
        "tags": n.tags,
        "notes": n.notes,
        "first_seen": n.first_seen.isoformat(),
        "last_seen": n.last_seen.isoformat(),
        "sources": n.sources,
        "author_type": n.author_type.value,
        "confidence": n.confidence,
        "props": n.props,
    }


def edge_to_dict(e: Edge) -> dict:
    return {
        "id": e.id,
        "type": e.type.value,
        "from": e.from_id,
        "to": e.to_id,
        "sources": e.sources,
        "first_seen": e.first_seen.isoformat(),
        "author_type": e.author_type.value,
        "props": e.props,
    }
