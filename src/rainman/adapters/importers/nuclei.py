"""nuclei (-jsonl / -json-export) importer → finding nodes + affects edges.

Each hit becomes a ``finding`` keyed by ``template-id[:matcher] @ matched-at``
so re-running the same scan upserts rather than duplicates, linked by
``affects`` to the asset it matched: the endpoint for URL matches, otherwise
the host or IP (PROPOSAL.md §7).
"""

from __future__ import annotations

from typing import Iterator

from ...domain.identity import host_of_url, normalize_ip
from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import emit_url, iter_json_lines


def _is_ip(value: str) -> bool:
    try:
        normalize_ip(value)
        return True
    except ValueError:
        return False


class NucleiImporter:
    name = "nuclei"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            if isinstance(rec, dict):
                yield from self._one(rec)

    def _one(self, rec: dict) -> Iterator[NodeOp | EdgeOp]:
        template = rec.get("template-id") or rec.get("templateID") or rec.get("template_id")
        matched = rec.get("matched-at") or rec.get("matched") or rec.get("host")
        if not template or not matched:
            return
        info = rec.get("info") or {}
        matcher = rec.get("matcher-name") or rec.get("matcher_name")
        severity = (info.get("severity") or "info").lower()
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        title = f"{template}{':' + matcher if matcher else ''} @ {matched}"
        props = {
            "kind": "suspected",
            "severity": severity,
            "template_id": template,
            "name": info.get("name"),
            "matcher": matcher,
            "matched_at": matched,
            "protocol": rec.get("type"),
            "extracted": rec.get("extracted-results"),
            "curl": rec.get("curl-command"),
            "reference": info.get("reference"),
        }
        props = {k: v for k, v in props.items() if v}
        yield NodeOp(
            NodeType.finding, title, source=self.name,
            tags=sorted({severity, *tags}), props=props,
            notes=info.get("description"),
        )

        # What does it affect? A URL → the endpoint; host[:port] → host or IP.
        if "://" in matched and rec.get("type", "http") == "http":
            yield from emit_url(matched, self.name, with_params=False)
            target_type, target = NodeType.endpoint, matched
        else:
            host = host_of_url(matched)
            if not host:
                return
            target_type = NodeType.ip if _is_ip(host) else NodeType.subdomain
            target = host
            yield NodeOp(target_type, target, source=self.name)
        yield EdgeOp(
            EdgeType.affects,
            NodeType.finding, title,
            target_type, target,
            source=self.name,
        )
