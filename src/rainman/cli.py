"""rainman CLI — import recon output and run the API.

    rainman import httpx out.json
    rainman import dnsx  resolved.jsonl
    rainman query 'type:endpoint code:403' | httpx -silent
    rainman leads
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
    result = svc.ingest(importer.parse(raw), program=args.program, tool=args.tool)
    repo.close()
    print(f"imported {args.tool} into program '{args.program}': {result}")
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


def _cmd_query(args: argparse.Namespace) -> int:
    from .adapters.api.serialize import export_value, node_to_dict
    from .domain.query import parse_query

    repo = SqliteGraphRepository(args.db)
    try:
        nodes, total = repo.query(
            parse_query(args.query), program=args.program, sort=args.sort,
            desc=not args.asc, limit=args.limit,
        )
    except ValueError as e:
        print(f"bad query: {e}", file=sys.stderr)
        return 2
    finally:
        repo.close()
    for n in nodes:
        print(json.dumps(node_to_dict(n)) if args.json else export_value(n))
    if total > len(nodes):
        print(f"# {len(nodes)} of {total} shown — raise --limit", file=sys.stderr)
    return 0


def _cmd_leads(args: argparse.Namespace) -> int:
    from .domain.query import LEADS, parse_query

    repo = SqliteGraphRepository(args.db)
    for lead in LEADS:
        _, total = repo.query(parse_query(lead["query"]), program=args.program, limit=1)
        if total or args.all:
            print(f"{total:>7}  {lead['name']:<34} {lead['query']}")
    repo.close()
    return 0


def _cmd_repair(args: argparse.Namespace) -> int:
    repo = SqliteGraphRepository(args.db)
    print(json.dumps(IngestService(repo).repair()))
    repo.close()
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
    pi.add_argument("--program", default="default", help="workspace to import into")
    pi.set_defaults(func=_cmd_import)

    pd = sub.add_parser("digest", help="print graph digest")
    pd.set_defaults(func=_cmd_digest)

    ps = sub.add_parser("serve", help="run the API server")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8000)
    ps.set_defaults(func=_cmd_serve)

    pq = sub.add_parser(
        "query", help="run a hunter query; prints one value/URL per line (pipe it into tools)",
    )
    pq.add_argument("query", help="e.g. 'type:endpoint code:403 -tag:archive'")
    pq.add_argument("--program", default=None, help="limit to one workspace")
    pq.add_argument("--limit", type=int, default=100000)
    pq.add_argument("--sort", default=None, help="value, first_seen, last_seen, links or a prop")
    pq.add_argument("--asc", action="store_true")
    pq.add_argument("--json", action="store_true", help="full nodes as JSONL")
    pq.set_defaults(func=_cmd_query)

    pe = sub.add_parser("leads", help="pre-baked hunts with match counts")
    pe.add_argument("--program", default=None)
    pe.add_argument("--all", action="store_true", help="include leads with zero matches")
    pe.set_defaults(func=_cmd_leads)

    pr = sub.add_parser("repair", help="attach un-rooted hosts to their apex domain")
    pr.set_defaults(func=_cmd_repair)

    pl = sub.add_parser("importers", help="list available importers")
    pl.set_defaults(func=_cmd_importers)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
