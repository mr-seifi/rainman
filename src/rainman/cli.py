"""rainman CLI — import recon output and run the API.

    rainman import httpx out.json
    rainman import dnsx  resolved.jsonl
    rainman digest
    rainman serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .adapters.importers import available, get_importer
from .adapters.store import SqliteGraphRepository
from .domain.ingest import IngestService

# Honor RAINMAN_DB so the CLI and the server agree on one file by default —
# in the Docker image both resolve to /data/rainman.db, so `rainman import`
# inside the container lands where the UI reads from.
DEFAULT_DB = os.environ.get("RAINMAN_DB", "rainman.db")


def _cmd_import(args: argparse.Namespace) -> int:
    try:
        importer = get_importer(args.tool)
    except KeyError as e:
        print(str(e), file=sys.stderr)
        return 2
    raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    repo = SqliteGraphRepository(args.db)
    svc = IngestService(repo)
    result = svc.ingest(importer.parse(raw))
    repo.close()
    print(f"imported {args.tool}: {result}")
    return 0


def _cmd_digest(args: argparse.Namespace) -> int:
    repo = SqliteGraphRepository(args.db)
    print(json.dumps(repo.digest(), indent=2))
    repo.close()
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .adapters.api import create_app

    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    return 0


def _cmd_importers(args: argparse.Namespace) -> int:
    print("\n".join(available()))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rainman", description=__doc__)
    p.add_argument(
        "--db", default=DEFAULT_DB,
        help=f"SQLite path (default {DEFAULT_DB!r}, from $RAINMAN_DB or 'rainman.db')",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("import", help="import a tool's output file")
    pi.add_argument("tool", help=f"one of: {', '.join(available())}")
    pi.add_argument("file", help="path to output file, or - for stdin")
    pi.set_defaults(func=_cmd_import)

    pd = sub.add_parser("digest", help="print graph digest")
    pd.set_defaults(func=_cmd_digest)

    ps = sub.add_parser("serve", help="run the API server")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8000)
    ps.set_defaults(func=_cmd_serve)

    pl = sub.add_parser("importers", help="list available importers")
    pl.set_defaults(func=_cmd_importers)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
