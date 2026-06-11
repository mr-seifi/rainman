"""katana (-json / -jsonl) importer → crawled endpoint + param nodes.

Handles both the nested form (``{"request":{"endpoint","method","source"},
"response":{"status_code"}}``) and the flat form. JS-sourced endpoints are
tagged so you can tell crawled-from-script apart from crawled-from-HTML.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, NodeOp
from .base import emit_url, iter_json_lines


class KatanaImporter:
    name = "katana"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            req = rec.get("request") or {}
            resp = rec.get("response") or {}
            url = req.get("endpoint") or rec.get("endpoint") or rec.get("url")
            if not url:
                continue
            source = req.get("source") or rec.get("source")
            tags = ["crawled"]
            if source and source.lower().endswith((".js", ".js.map")):
                tags.append("js-sourced")
            yield from emit_url(
                url,
                self.name,
                method=req.get("method") or rec.get("method"),
                status=resp.get("status_code") or rec.get("status_code"),
                length=resp.get("content_length"),
                tags=tags,
                extra_props={"crawl_source": source} if source else None,
            )
