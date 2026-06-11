"""waybackurls importer → archived endpoint + param nodes (Wayback only).

Same shape as gau; dedupes into the same archived endpoint/parameter nodes
since both emit through the canonical URL path.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, NodeOp
from .base import emit_url, iter_lines


class WaybackurlsImporter:
    name = "waybackurls"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for url in iter_lines(raw):
            yield from emit_url(url, self.name, tags=["archive"])
