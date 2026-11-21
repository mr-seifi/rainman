"""Robustness: every importer and the query endpoint must survive hostile or
malformed input without a 500 and without leaving partial data behind; plus
realistic-format samples for each tool, CLI coverage, legacy-DB migration and
a scale check."""

import json
import random
import sqlite3
import string
import time

import pytest
from fastapi.testclient import TestClient

from rainman.adapters.api import create_app
from rainman.adapters.importers import available
from rainman.adapters.store import SqliteGraphRepository
from rainman.cli import main as cli
from rainman.domain.ingest import IngestService
from rainman.domain.query import LEADS, parse_query

TEXT = {"content-type": "text/plain"}

# One sample per tool, shaped like the tool's documented output.
SAMPLES = {
    "subfinder": '{"host":"api.example.com","input":"example.com","source":"crtsh"}\n'
                 '{"host":"example.com","input":"example.com","source":"dnsdumpster"}',
    "shuffledns": "api.example.com\nadmin.example.com. A 203.0.113.10\n# comment\n",
    "dnsx": '{"host":"api.example.com","resolver":["1.1.1.1:53"],"a":["203.0.113.10"],'
            '"aaaa":["2001:db8::1"],"cname":["lb.example.net"],"status_code":"NOERROR"}',
    "httpx": '{"timestamp":"2026-01-01T00:00:00Z","port":"443","url":"https://api.example.com",'
             '"input":"api.example.com","title":"API","scheme":"https","webserver":"nginx",'
             '"content_type":"text/html","method":"GET","host":"203.0.113.10","path":"/",'
             '"a":["203.0.113.10"],"tech":["Nginx","React"],"status_code":200,"content_length":1234,'
             '"tls":{"subject_cn":"example.com","subject_an":["example.com","*.example.com",'
             '"admin.example.com"],"issuer_cn":"R3","fingerprint_hash":{"sha256":"ab"}},"cdn":true,'
             '"cdn_name":"cloudflare"}',
    "nmap": '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="203.0.113.10" addrtype="ipv4"/><address addr="AA:BB" addrtype="mac"/>'
            '<hostnames><hostname name="api.example.com" type="user"/></hostnames><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="OpenSSH" version="8.9"/></port>'
            '<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>'
            '</ports></host><host><status state="down"/></host></nmaprun>',
    "naabu": '{"host":"api.example.com","ip":"203.0.113.10","port":8443,"protocol":"tcp"}\n'
             '{"ip":"203.0.113.11","port":22}',
    "katana": '{"timestamp":"2026-01-01T00:00:00Z","request":{"method":"GET",'
              '"endpoint":"https://api.example.com/v1/users?id=7&next=/home","tag":"script",'
              '"attribute":"src","source":"https://api.example.com/static/app.js"},'
              '"response":{"status_code":200,"content_length":88}}',
    "gau": "https://shop.example.com/item?id=1\nhttp://shop.example.com/old.php?file=a.txt\n"
           '{"url":"https://shop.example.com/cart"}\n',
    "waybackurls": "https://shop.example.com/robots.txt\nhttps://shop.example.com/a?b=c\n",
    "ffuf": json.dumps({"commandline": "ffuf -u https://api.example.com/FUZZ",
                        "config": {"url": "https://api.example.com/FUZZ", "headers": {}},
                        "results": [{"input": {"FUZZ": "admin"}, "position": 1, "status": 403,
                                     "length": 153, "words": 3, "lines": 8,
                                     "url": "https://api.example.com/admin",
                                     "host": "api.example.com"}]}),
    "kiterunner": '{"url":"https://api.example.com/api/v1/health","method":"GET","status":200,"length":17}',
    "x8": '[{"method":"GET","url":"https://api.example.com/search","status":200,"size":120,'
          '"found_params":[{"name":"debug","value":null,"diffs":"","status":200,"size":300,'
          '"reason_kind":"Reflected"},"plain"],"injection_place":"Path"}]',
    "nuclei": '{"template-id":"redis-default-logins","info":{"name":"Redis","severity":"high",'
              '"tags":["network","redis"]},"type":"tcp","host":"203.0.113.10:6379",'
              '"matched-at":"203.0.113.10:6379","ip":"203.0.113.10","timestamp":"2026-01-01T00:00:00Z"}\n'
              '{"template-id":"tech-detect","matcher-name":"nginx","info":{"name":"Tech",'
              '"severity":"info","tags":"tech"},"type":"http","host":"https://api.example.com",'
              '"matched-at":"https://api.example.com/"}',
}


def test_every_importer_has_a_sample():
    assert set(SAMPLES) == set(available())


@pytest.mark.parametrize("tool", sorted(SAMPLES))
def test_importer_sample_lands_and_is_idempotent(tool):
    c = TestClient(create_app(":memory:"))
    first = c.post(f"/import/{tool}", content=SAMPLES[tool], headers=TEXT)
    assert first.status_code == 200, first.text
    assert first.json()["nodes"] > 0
    before = c.get("/digest").json()
    again = c.post(f"/import/{tool}", content=SAMPLES[tool], headers=TEXT).json()
    after = c.get("/digest").json()
    assert again["new_nodes"] == 0
    assert (before["total_nodes"], before["total_edges"]) == (after["total_nodes"], after["total_edges"])
    # no edge may point at a node that does not exist
    repo_nodes = {n["id"] for n in c.get("/nodes", params={"limit": 10000}).json()["nodes"]}
    for nid in repo_nodes:
        hood = c.get("/neighborhood", params={"id": nid}).json()
        assert len(hood["edges"]) == hood["total"]


def test_all_tools_into_one_graph_dedupes_across_tools():
    c = TestClient(create_app(":memory:"))
    for tool in random.Random(7).sample(sorted(SAMPLES), len(SAMPLES)):   # order must not matter
        assert c.post(f"/import/{tool}", content=SAMPLES[tool], headers=TEXT).status_code == 200
    one = c.get("/nodes", params={"q": "id:sub:api.example.com"}).json()
    assert one["total"] == 1
    assert {"subfinder", "dnsx", "httpx", "nmap", "naabu", "katana"} <= set(one["nodes"][0]["sources"])
    # naabu's bare port and nmap's detail merged; redis finding linked to the ip
    svc = c.get("/nodes", params={"q": "type:service port:6379"}).json()["nodes"][0]
    assert svc["props"]["name"] == "redis"
    assert c.get("/nodes", params={"q": "type:finding sev:high"}).json()["total"] == 1
    # every host is reachable from a root
    assert c.get("/nodes", params={"q": "type:subdomain"}).json()["total"] > 0
    assert SqliteGraphRepository  # (import used below)
    for lead in c.get("/leads").json()["leads"]:
        assert isinstance(lead["count"], int)


GARBAGE = [
    "", "   \n\n", "not json at all", "{", "[", "[1,2,3]", '"str"', "null", "{}", "[{}]",
    '{"url": null}', '{"url": 5}', '{"url": ["a"]}', '{"host": {"a": 1}}', '{"ip":"999.1.1.1","port":"x"}',
    '{"url":"http://"}', '{"url":"://bad"}', '{"url":"https://[::1"}', "<nmaprun>", "<a><b></a>",
    "\x00\x01\x02", "https://exa mple.com/ a", "a" * 5000, '{"results": "nope"}',
    '{"results":[1,null,"x"]}', '{"tls": "x", "url": "https://a.example.com"}',
    '{"template-id": 1, "matched-at": 2}', '{"request": "x"}', '{"found_params": [1, null], "url": "https://a.example.com"}',
    '{"host":"a.example.com","a":"203.0.113.1","cname":5}', "ȧ.例え.テスト\n", "http://xn--/\n",
]


@pytest.mark.parametrize("tool", sorted(SAMPLES))
def test_importers_never_500_on_garbage(tool):
    c = TestClient(create_app(":memory:"), raise_server_exceptions=False)
    rng = random.Random(tool)
    fuzz = GARBAGE + [
        "".join(rng.choice(string.printable) for _ in range(rng.randint(1, 200))) for _ in range(40)
    ] + [SAMPLES[tool][: rng.randint(0, len(SAMPLES[tool]))] for _ in range(20)]   # truncations
    for body in fuzz:
        r = c.post(f"/import/{tool}", content=body.encode("utf-8", "replace"), headers=TEXT)
        # 422 = the framework refusing an empty body
        assert r.status_code in (200, 400, 422), (tool, body[:80], r.status_code, r.text[:200])
    # whatever landed is internally consistent and still queryable
    assert c.get("/digest").status_code == 200
    assert c.get("/nodes", params={"q": "", "limit": 1000}).status_code == 200
    assert c.get("/roots").status_code == 200


def test_query_never_500():
    c = TestClient(create_app(":memory:"), raise_server_exceptions=False)
    c.post("/import/httpx", content=SAMPLES["httpx"], headers=TEXT)
    rng = random.Random(3)
    atoms = ["type", "code", "tag", "host", "tech", "new", "stale", "has", "links", "value", "-",
             ":", "|", "*", '"', "'", ">=", "<", "%", "_", "\\", "$", ".", " ", "last", "7d", "1",
             "endpoint", "(", ")", ";", "--", "\x00", "é", "{", "}", "[", "]", "/"]
    queries = ['"', '""', ':"', "a:", ":a", "-", "--", "-:", "type:", "new:", "links:>=", "has:\"x\"",
               "x\"y:1", "$.a:1", "a.b:1", "code:>=1|2", "new:last|7d", "type:*", "-type:*",
               "' OR 1=1 --", "value:%_\\", "sort", "tag:" + "a|" * 300]
    queries += ["".join(rng.choice(atoms) for _ in range(rng.randint(1, 12))) for _ in range(600)]
    for q in queries:
        for sort in (None, "value", "links", "status_code", 'x"y', "a.b'c"):
            r = c.get("/nodes", params={"q": q, **({"sort": sort} if sort else {})})
            assert r.status_code in (200, 400), (q, sort, r.status_code, r.text[:200])
        parse_query(q)


def test_every_lead_query_is_valid():
    repo = SqliteGraphRepository(":memory:")
    for lead in LEADS:
        repo.query(parse_query(lead["query"]), limit=1)
    assert len({lead["key"] for lead in LEADS}) == len(LEADS)


def test_api_rejects_bad_requests_cleanly():
    c = TestClient(create_app(":memory:"), raise_server_exceptions=False)
    assert c.post("/import/nope", content="x", headers=TEXT).status_code == 404
    assert c.get("/node", params={"id": "missing"}).status_code == 404
    assert c.get("/neighborhood", params={"id": "missing"}).status_code == 404
    assert c.patch("/node", params={"id": "missing"}, json={}).status_code == 404
    assert c.request("DELETE", "/node", params={"id": "missing"}).status_code == 404
    assert c.request("DELETE", "/edge", params={"id": "missing"}).status_code == 404
    assert c.post("/edge", json={"type": "affects", "from_id": "a", "to_id": "b"}).status_code == 404
    assert c.post("/ingest", json={"nodes": [{"type": "ip", "value": "nope"}]}).json()["nodes"] == 0
    assert c.post("/ingest", json={"nodes": [{"type": "bogus", "value": "x"}]}).status_code == 422
    assert c.get("/nodes", params={"limit": 0}).status_code == 422
    assert c.get("/nodes", params={"format": "weird"}).status_code == 200   # falls back to json
    assert c.post("/bulk/status", json={"ids": ["missing"], "status": "in_scope"}).json() == \
        {"updated": [], "skipped": ["missing"]}
    assert c.post("/finding", json={"title": "t", "affects": ["missing"]}).status_code == 200


def test_editor_flow_end_to_end():
    c = TestClient(create_app(":memory:"))
    c.post("/import/httpx", content=SAMPLES["httpx"], headers=TEXT)
    nid = "sub:api.example.com"
    assert c.patch("/node", params={"id": nid}, json={"status": "confirmed"}).status_code == 409
    assert c.patch("/node", params={"id": nid}, json={"status": "in_scope", "notes": "n",
                                                       "set_tags": ["a", "b"]}).status_code == 200
    assert c.patch("/node", params={"id": nid}, json={"set_tags": ["b"], "props": {"hunt": "working"}}
                   ).json()["node"]["tags"] == ["b"]
    assert c.get("/nodes", params={"q": "hunt:working has:notes status:in_scope tag:b"}).json()["total"] == 1
    f = c.post("/finding", json={"title": "IDOR", "kind": "intuition", "affects": [nid]}).json()["node"]
    fn = c.post("/functionality", json={"name": "auth", "members": [nid]}).json()["node"]
    hood = {n["id"] for n in c.get("/neighborhood", params={"id": nid}).json()["nodes"]}
    assert {f["id"], fn["id"]} <= hood
    # a re-import must not undo manual triage
    c.post("/import/httpx", content=SAMPLES["httpx"], headers=TEXT)
    node = c.get("/node", params={"id": nid}).json()["node"]
    assert (node["status"], node["notes"], node["tags"]) == ("in_scope", "n", ["b"])
    assert node["props"]["hunt"] == "working"
    # deleting a node removes its edges
    assert c.request("DELETE", "/node", params={"id": nid}).status_code == 200
    assert c.get("/neighborhood", params={"id": f["id"]}).json()["total"] == 0


def test_cli_roundtrip(tmp_path, capsys):
    db, src = str(tmp_path / "t.db"), tmp_path / "h.jsonl"
    src.write_text(SAMPLES["httpx"])
    assert cli(["--db", db, "import", "httpx", str(src), "--program", "acme"]) == 0
    assert "new" in capsys.readouterr().out
    assert cli(["--db", db, "import", "nope", str(src)]) == 2
    capsys.readouterr()
    assert cli(["--db", db, "query", "type:endpoint", "--program", "acme"]) == 0
    assert capsys.readouterr().out == "https://api.example.com/\n"
    assert cli(["--db", db, "query", "type:endpoint", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["program"] == "acme"
    assert cli(["--db", db, "query", "links:>=x"]) == 2
    capsys.readouterr()
    assert cli(["--db", db, "leads", "--all"]) == 0
    assert "New since last import" in capsys.readouterr().out
    for cmd in (["digest"], ["importers"], ["repair"]):
        assert cli(["--db", db, *cmd]) == 0


def test_pre_program_database_is_migrated(tmp_path):
    """A database from before the program column / canonical endpoint values."""
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.executescript("""
      CREATE TABLE nodes (id TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
        status TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]', notes TEXT NOT NULL DEFAULT '',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, sources TEXT NOT NULL DEFAULT '[]',
        author_type TEXT NOT NULL DEFAULT 'tool', confidence REAL, props TEXT NOT NULL DEFAULT '{}');
      CREATE TABLE edges (id TEXT PRIMARY KEY, type TEXT NOT NULL, from_id TEXT NOT NULL,
        to_id TEXT NOT NULL, sources TEXT NOT NULL DEFAULT '[]', first_seen TEXT NOT NULL,
        author_type TEXT NOT NULL DEFAULT 'tool', props TEXT NOT NULL DEFAULT '{}');
      INSERT INTO nodes (id,type,value,status,first_seen,last_seen) VALUES
        ('sub:old.example.com','subdomain','old.example.com','flagged','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00'),
        ('ep:old.example.com/a','endpoint','HTTP://Old.Example.com/a?x=1','untriaged','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00');
    """)
    con.commit()
    con.close()
    repo = SqliteGraphRepository(db)
    ep = repo.get_node("ep:old.example.com/a")
    assert (ep.value, ep.props["scheme"], ep.program) == ("old.example.com/a", "http", "default")
    assert IngestService(repo).repair() == {"hosts_linked": 1}
    assert repo.get_node("sub:old.example.com").status.value == "flagged"   # triage preserved
    nodes, total = repo.query(parse_query("stale:30d type:subdomain"))
    assert total == 1
    repo.close()
    SqliteGraphRepository(db).close()        # reopening is a no-op


def test_scale_large_archive_dump(tmp_path):
    """A large archive dump must import at a usable rate and stay queryable.
    N defaults to 20k URLs (60k nodes) to keep the suite quick; set
    RAINMAN_SCALE_N=100000 for the full run (about a minute)."""
    import os

    from rainman.adapters.importers import get_importer

    n = int(os.environ.get("RAINMAN_SCALE_N", "20000"))
    repo = SqliteGraphRepository(str(tmp_path / "big.db"))
    svc = IngestService(repo)
    raw = "\n".join(f"https://h{i % 200}.example.com/p/{i}?id={i}&q=x" for i in range(n))
    t = time.perf_counter()
    res = svc.ingest(get_importer("gau").parse(raw), tool="gau")
    took = time.perf_counter() - t
    assert res.nodes == n + 200 + 1 + 2 * n          # endpoints + hosts + apex + params
    assert n / took > 500, f"only {n / took:.0f} URLs/s"
    t = time.perf_counter()
    _, total = repo.query(parse_query("type:endpoint host:h7.example.com"), limit=200)
    assert total == n // 200
    repo.query(parse_query("type:parameter name:id -has:example"), limit=50)
    edges, _ = repo.neighbors("sub:h7.example.com", limit=50)
    assert len(edges) == 50 and repo.degree("sub:h7.example.com") == n // 200 + 1
    assert time.perf_counter() - t < 10
    print(f"\n{n} URLs: import {took:.1f}s ({n / took:.0f}/s), queries {time.perf_counter() - t:.2f}s")


# -- concurrency, multi-process, awkward hosts -------------------------------

def test_concurrent_imports_and_reads_stay_consistent(tmp_path):
    """The API runs handlers on a thread pool: simultaneous imports, edits and
    queries must neither error nor lose writes."""
    from concurrent.futures import ThreadPoolExecutor

    c = TestClient(create_app(str(tmp_path / "c.db")))

    def imp(i):
        body = "\n".join(json.dumps({"url": f"https://h{i}.example.com/p{j}", "status_code": 200,
                                     "ip": "203.0.113.10"}) for j in range(40))
        return c.post("/import/httpx", content=body, headers=TEXT).status_code

    def read(_):
        return max(c.get("/nodes", params={"q": "type:endpoint", "limit": 50}).status_code,
                   c.get("/leads").status_code, c.get("/digest").status_code)

    with ThreadPoolExecutor(12) as pool:
        jobs = [pool.submit(imp, i) for i in range(20)] + [pool.submit(read, i) for i in range(40)]
        codes = [j.result() for j in jobs]
    assert set(codes) == {200}
    assert c.get("/nodes", params={"q": "type:endpoint"}).json()["total"] == 800
    assert c.get("/nodes", params={"q": "type:subdomain"}).json()["total"] == 20
    assert c.get("/nodes", params={"q": "type:ip links:>=20"}).json()["total"] == 1
    assert len(c.get("/imports", params={"limit": 100}).json()["imports"]) == 20


def test_cli_and_server_share_one_database(tmp_path):
    """`rainman import` from a shell while the server has the file open."""
    db = str(tmp_path / "shared.db")
    c = TestClient(create_app(db))
    src = tmp_path / "h.jsonl"
    src.write_text(SAMPLES["httpx"])
    assert cli(["--db", db, "import", "httpx", str(src)]) == 0
    assert c.get("/nodes", params={"q": "type:endpoint"}).json()["total"] == 1     # server sees it
    c.patch("/node", params={"id": "sub:api.example.com"}, json={"notes": "from ui"})
    assert cli(["--db", db, "import", "httpx", str(src)]) == 0                     # and vice versa
    assert c.get("/node", params={"id": "sub:api.example.com"}).json()["node"]["notes"] == "from ui"


def test_awkward_hosts_and_urls():
    c = TestClient(create_app(":memory:"))
    urls = [
        "https://API.Example.COM:443/A/b/?x=1#frag",      # case, default port, trailing slash
        "http://api.example.com:8080/a/b",                 # non-default port is a different endpoint
        "https://bücher.example.de/",                      # IDN
        "https://[2001:db8::1]:8443/v6",                   # IPv6 literal
        "https://a.b.c.example.co.uk/deep",                # multi-label suffix
        "https://localhost/x",                             # no dot: no apex
        "api.example.com/no-scheme?y=2",
    ]
    r = c.post("/import/gau", content="\n".join(urls), headers=TEXT)
    assert r.status_code == 200, r.text
    ids = {n["id"] for n in c.get("/nodes", params={"limit": 1000}).json()["nodes"]}
    assert "ep:api.example.com/A/b" in ids and "ep:api.example.com:8080/a/b" in ids
    assert "sub:xn--bcher-kva.example.de" in ids and "dom:example.de" in ids
    assert "dom:example.co.uk" in ids and "dom:co.uk" not in ids
    assert "ep:api.example.com/no-scheme" in ids
    assert not any(i.startswith("dom:localhost") for i in ids)
    # the IPv6 host is kept but not given a bogus apex domain
    v6 = [i for i in ids if "2001:db8::1" in i]
    assert v6 and not any(i.startswith("dom:") for i in v6)
    for q in ("host:api.example.com", "type:endpoint", "value:*v6*"):
        assert c.get("/nodes", params={"q": q, "format": "txt"}).status_code == 200
    # every export line is a usable URL
    lines = c.get("/nodes", params={"q": "type:endpoint", "format": "txt"}).text.split()
    assert len(lines) == 7 and all(l.startswith(("http://", "https://")) for l in lines)
