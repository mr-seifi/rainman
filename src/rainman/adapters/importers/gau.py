"""gau importer → passive/archived endpoint + param nodes.

Accepts a plain URL list or ``--json`` ({"url": ...}). Archived URLs are not
probed, so they're tagged ``source=archive`` — pair with httpx for live status.
"""

from __future__ import annotations

import json
from typing import Iterator

from ...domain.model import EdgeOp, NodeOp
from .base import emit_url, iter_lines


class GauImporter:
    name = "gau"
    _tag = "archive"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for line in iter_lines(raw):
            url = line
            if line[0] in "{[":
                try:
                    obj = json.loads(line)
                    url = obj.get("url") if isinstance(obj, dict) else None
                except json.JSONDecodeError:
                    url = line
            if not url:
                continue
            yield from emit_url(url, self.name, tags=[self._tag])
