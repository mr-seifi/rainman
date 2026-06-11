"""kiteRunner (kr -j) importer → API-focused endpoint nodes (kind=api).

Route-based discovery hits are tagged so API surface is filterable apart from
generic content discovery.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, NodeOp
from .base import emit_url, iter_json_lines


class KiteRunnerImporter:
    name = "kiterunner"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            url = rec.get("url") or rec.get("endpoint")
            if not url:
                continue
            yield from emit_url(
                url,
                self.name,
                method=rec.get("method"),
                status=rec.get("status") or rec.get("status_code"),
                length=rec.get("length") or rec.get("content_length"),
                tags=["api"],
                extra_props={"kind": "api"},
            )
