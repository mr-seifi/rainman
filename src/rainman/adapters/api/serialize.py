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
        "program": n.program,
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


def export_value(n: Node) -> str:
    """The form you would feed back into a tool: endpoints and parameters
    become full URLs (their graph identity drops the scheme), everything else
    is its plain value."""
    scheme = n.props.get("scheme") or "https"
    if n.type.value == "endpoint":
        return f"{scheme}://{n.value}"
    if n.type.value == "parameter" and "#" in n.value:
        url, name = n.value.rsplit("#", 1)
        return f"{scheme}://{url}?{name}={n.props.get('example', '')}"
    return n.value
