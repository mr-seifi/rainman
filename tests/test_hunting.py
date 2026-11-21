"""Query language, leads, new-since-import, export, nuclei, and the ingest
guarantees (atomic, no dropped data, no dangling edges)."""

import json

import pytest
from fastapi.testclient import TestClient

from rainman.adapters.api import create_app
from rainman.adapters.importers import get_importer
from rainman.adapters.store import SqliteGraphRepository
from rainman.domain.ingest import IngestService
from rainman.domain.model import NodeOp, NodeType, Status
from rainman.domain.query import parse_query

TEXT = {"content-type": "text/plain"}

HTTPX = "\n".join(json.dumps(r) for r in [
    {"url": "https://api.example.com/v2/users", "status_code": 200, "title": "Users API",
     "tech": ["nginx", "Node.js"], "ip": "203.0.113.10", "content_length": 512},
    {"url": "https://api.example.com/admin", "status_code": 403, "tech": ["nginx"],
     "ip": "203.0.113.10"},
    {"url": "https://dev.example.com/.git/config", "status_code": 200, "ip": "203.0.113.11"},
    {"url": "https://shop.example.com/", "status_code": 500, "tech": ["PHP"]},
])
KATANA = json.dumps({"request": {"endpoint": "https://api.example.com/go?redirect_uri=x&q=1",
                                 "method": "POST", "source": "https://api.example.com/app.js"},
                     "response": {"status_code": 302}})
NUCLEI = json.dumps({
    "template-id": "git-config", "matched-at": "https://dev.example.com/.git/config",
    "type": "http", "host": "https://dev.example.com",
    "info": {"name": "Git Config Exposure", "severity": "medium", "tags": ["exposure", "git"]},
})


@pytest.fixture
def c():
    client = TestClient(create_app(":memory:"))
    assert client.post("/import/httpx", content=HTTPX, headers=TEXT).status_code == 200
    assert client.post("/import/katana", content=KATANA, headers=TEXT).status_code == 200
    return client


def q(c, query, **params):
    r = c.get("/nodes", params={"q": query, **params})
    assert r.status_code == 200, r.text
    return r.json()


def values(c, query, **params):
    return {n["value"] for n in q(c, query, **params)["nodes"]}


# -- query language ---------------------------------------------------------

def test_parse_query_terms():
    terms = parse_query('type:endpoint code:>=400 -tag:archive title:"admin panel" login a|b')
    assert [(t.key, t.values, t.op, t.negate) for t in terms] == [
        ("type", ["endpoint"], "=", False),
        ("status_code", ["400"], ">=", False),      # code → status_code alias
        ("tag", ["archive"], "=", True),
        ("title", ["admin panel"], "=", False),
        (None, ["login"], "=", False),
        (None, ["a", "b"], "=", False),
    ]
    # a URL is free text, not key "https"
    assert parse_query("https://x.com/a")[0].key is None


def test_filter_by_prop_and_wildcard(c):
    assert values(c, "type:endpoint code:403") == {"api.example.com/admin"}
    assert values(c, "type:endpoint code:4*|5*") == {"api.example.com/admin", "shop.example.com/"}
    assert values(c, "type:endpoint code:>=500") == {"shop.example.com/"}
    assert values(c, 'title:"users api"') == {"api.example.com/v2/users"}


def test_negation_keeps_nodes_without_the_prop(c):
    got = values(c, "type:endpoint -code:200")
    # the katana endpoint has status 302, others non-200 stay; 200s go
    assert "api.example.com/v2/users" not in got and "api.example.com/admin" in got
    assert values(c, "type:subdomain -code:200") == values(c, "type:subdomain")


def test_host_tech_and_links(c):
    assert values(c, "type:endpoint host:shop.example.com") == {"shop.example.com/"}
    assert values(c, "type:subdomain tech:php") == {"shop.example.com"}
    # tech reaches endpoints through their host
    assert "api.example.com/admin" in values(c, "type:endpoint tech:nginx")
    # api has 3 endpoints, 2 techs, an ip and its apex; the others have 3 links
    assert values(c, "type:subdomain links:>=4") == {"api.example.com"}


def test_params_and_has(c):
    assert values(c, "type:parameter name:redirect*") == {"api.example.com/go#redirect_uri"}
    assert values(c, "type:endpoint has:crawl_source") == {"api.example.com/go"}
    assert values(c, "tag:js-sourced") == {"api.example.com/go"}


def test_sort_paging_and_total(c):
    page = q(c, "type:endpoint", sort="status_code", order="asc", limit=2)
    assert page["total"] == 5 and len(page["nodes"]) == 2
    assert [n["props"]["status_code"] for n in page["nodes"]] == [200, 200]
    # nodes without the prop sort last in both directions
    for order in ("asc", "desc"):
        got = q(c, "", sort="status_code", order=order, limit=1000)["nodes"]
        codes = [n["props"].get("status_code") for n in got]
        first_blank = codes.index(None)
        assert all(x is None for x in codes[first_blank:]) and first_blank == 5


def test_bad_query_is_a_400(c):
    assert c.get("/nodes", params={"q": "code:>=abc"}).status_code == 400
    assert c.get("/nodes", params={"q": "new:whenever"}).status_code == 400


def test_like_metacharacters_are_literal(c):
    assert values(c, "value:%") == set()
    assert values(c, "type:parameter name:redirect_uri") == {"api.example.com/go#redirect_uri"}
    assert values(c, "type:parameter name:redirectXuri") == set()


# -- new since last import, history ----------------------------------------

def test_new_since_last_import(c):
    r = c.post("/import/httpx", headers=TEXT,
               content='{"url":"https://new.example.com/","status_code":200}')
    assert r.json()["new_nodes"] == 2          # host + endpoint; apex already known
    assert values(c, "new:last") == {"new.example.com", "new.example.com/"}
    assert c.get("/imports").json()["imports"][0]["tool"] == "httpx"


def test_status_code_change_is_kept(c):
    c.post("/import/httpx", headers=TEXT,
           content='{"url":"https://api.example.com/admin","status_code":200}')
    node = q(c, "type:endpoint has:status_code_history")["nodes"][0]
    assert node["props"]["status_code"] == 200
    assert node["props"]["status_code_history"][0]["code"] == 403


def test_observed_method_is_not_overwritten(c):
    # gau knows nothing about the method; it must not reset katana's POST
    c.post("/import/gau", content="https://api.example.com/go?q=2\n", headers=TEXT)
    assert q(c, "id:ep:api.example.com/go")["nodes"][0]["props"]["method"] == "POST"


# -- leads and export -------------------------------------------------------

def test_leads_counts(c):
    leads = {l["key"]: l["count"] for l in c.get("/leads").json()["leads"]}
    assert leads["auth_walls"] == 1
    assert leads["errors"] == 1
    assert leads["sensitive_paths"] == 1
    assert leads["dev_hosts"] == 1
    assert leads["juicy_params"] == 1          # redirect_uri; plain "q" is not flagged
    assert leads["js_endpoints"] == 1


def test_export_formats(c):
    txt = c.get("/nodes", params={"q": "type:endpoint code:403", "format": "txt"}).text
    assert txt == "https://api.example.com/admin\n"
    csv_ = c.get("/nodes", params={"q": "type:endpoint code:403", "format": "csv"}).text
    assert csv_.splitlines()[0].startswith("type,value,url") and "403" in csv_
    line = c.get("/nodes", params={"q": "code:403", "format": "jsonl"}).text.strip()
    assert json.loads(line)["id"] == "ep:api.example.com/admin"


# -- nuclei -----------------------------------------------------------------

def test_nuclei_finding_affects_endpoint(c):
    assert c.post("/import/nuclei", content=NUCLEI, headers=TEXT).status_code == 200
    finding = q(c, "type:finding sev:medium")["nodes"][0]
    assert finding["props"]["template_id"] == "git-config"
    assert "exposure" in finding["tags"]
    hood = c.get("/neighborhood", params={"id": finding["id"]}).json()
    assert [n["id"] for n in hood["nodes"]] == ["ep:dev.example.com/.git/config"]
    # idempotent
    c.post("/import/nuclei", content=NUCLEI, headers=TEXT)
    assert q(c, "type:finding")["total"] == 1


def test_nuclei_network_match_affects_host():
    ops = list(get_importer("nuclei").parse(json.dumps({
        "template-id": "redis-unauth", "matched-at": "203.0.113.10:6379", "type": "tcp",
        "info": {"severity": "high"}})))
    assert any(getattr(o, "to_value_type", None) == NodeType.ip for o in ops)


# -- ingest guarantees ------------------------------------------------------

def test_batch_merges_repeat_mentions_instead_of_dropping():
    repo = SqliteGraphRepository(":memory:")
    IngestService(repo).ingest([
        NodeOp(NodeType.ip, "203.0.113.5", source="dnsx"),
        NodeOp(NodeType.ip, "203.0.113.5", source="dnsx", props={"ptr": "a.example.com"},
               tags=["x"]),
    ])
    node = repo.get_node("ip:203.0.113.5")
    assert node.props["ptr"] == "a.example.com" and node.tags == ["x"]


def test_import_is_atomic_and_bad_records_do_not_abort():
    repo = SqliteGraphRepository(":memory:")
    svc = IngestService(repo)

    def boom():
        yield NodeOp(NodeType.subdomain, "a.example.com", source="t")
        raise RuntimeError("parser died")

    with pytest.raises(RuntimeError):
        svc.ingest(boom())
    assert repo.digest()["total_nodes"] == 0

    res = svc.ingest([
        NodeOp(NodeType.ip, "not-an-ip", source="t"),
        NodeOp(NodeType.ip, "203.0.113.5", source="t"),
    ])
    assert (res.nodes, res.skipped) == (1, 1)


def test_ffuf_param_mode_has_no_dangling_edge():
    c = TestClient(create_app(":memory:"))
    ffuf = json.dumps({"config": {"url": "https://api.example.com/search?FUZZ=1"},
                       "results": [{"url": "https://api.example.com/search?debug=1",
                                    "status": 200, "input": {"FUZZ": "debug"}}]})
    c.post("/import/ffuf", content=ffuf, headers=TEXT)
    hood = c.get("/neighborhood", params={"id": "ep:api.example.com/search"}).json()
    assert "param:api.example.com/search#debug" in {n["id"] for n in hood["nodes"]}


def test_ingest_cannot_bypass_the_state_machine(c):
    body = {"nodes": [{"type": "subdomain", "value": "api.example.com", "status": "confirmed"}]}
    c.post("/ingest", json=body)
    assert q(c, "id:sub:api.example.com")["nodes"][0]["status"] == Status.untriaged.value


def test_neighborhood_reports_truncation(c):
    hood = c.get("/neighborhood", params={"id": "sub:api.example.com", "limit": 2}).json()
    assert hood["truncated"] and hood["total"] > 2 and len(hood["edges"]) == 2


def test_repair_links_legacy_hosts():
    repo = SqliteGraphRepository(":memory:")
    repo.upsert_node(NodeOp(NodeType.subdomain, "old.example.com", source="legacy"))
    assert IngestService(repo).repair() == {"hosts_linked": 1}
    assert repo.get_node("dom:example.com") is not None
    assert IngestService(repo).repair() == {"hosts_linked": 0}


# -- browser-as-a-bridge protection ----------------------------------------

def test_cross_origin_writes_are_refused(c):
    r = c.post("/import/httpx", content="{}", headers={**TEXT, "origin": "https://evil.example"})
    assert r.status_code == 403
    r = c.request("DELETE", "/node", params={"id": "sub:api.example.com"},
                  headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    # same-origin and non-browser clients still work, and no CORS grant is sent
    ok = c.post("/import/httpx", content="{}", headers={**TEXT, "origin": "http://testserver"})
    assert ok.status_code == 200
    assert "access-control-allow-origin" not in c.get("/digest", headers={"origin": "https://evil.example"}).headers
