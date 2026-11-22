"""Agent surface: the tools an agent walks the graph with, and the MCP
transports (stdio and HTTP) that expose them."""

import io
import json

import pytest
from fastapi.testclient import TestClient

from rainman.adapters.agent import AgentTools, McpServer, ToolError
from rainman.adapters.api import create_app
from rainman.adapters.importers import get_importer
from rainman.adapters.store import SqliteGraphRepository
from rainman.cli import main
from rainman.domain.ingest import IngestService

HTTPX = "\n".join(json.dumps(r) for r in [
    {"url": "https://api.example.com/v2/users", "status_code": 200, "title": "Users API",
     "tech": ["nginx", "Node.js"], "ip": "203.0.113.10", "content_length": 512},
    {"url": "https://api.example.com/admin", "status_code": 403, "tech": ["nginx"],
     "ip": "203.0.113.10"},
    {"url": "https://dev.example.com/.git/config", "status_code": 200, "ip": "203.0.113.10"},
    {"url": "https://shop.example.com/", "status_code": 500, "tech": ["nginx", "PHP"],
     "ip": "203.0.113.20"},
])
KATANA = json.dumps({"request": {"endpoint": "https://api.example.com/go?redirect_uri=x&q=1",
                                 "method": "POST"}, "response": {"status_code": 302}})
NUCLEI = json.dumps({
    "template-id": "git-config", "matched-at": "https://dev.example.com/.git/config",
    "type": "http", "host": "https://dev.example.com",
    "info": {"name": "Git Config Exposure", "severity": "medium", "tags": ["exposure"]},
})


def _load(repo, program="default"):
    svc = IngestService(repo)
    for tool, raw in (("httpx", HTTPX), ("katana", KATANA), ("nuclei", NUCLEI)):
        svc.ingest(get_importer(tool).parse(raw), program=program, tool=tool)


@pytest.fixture
def repo():
    r = SqliteGraphRepository(":memory:")
    _load(r)
    yield r
    r.close()


@pytest.fixture
def t(repo):
    return AgentTools(repo)


def ids(rows):
    return {r["id"] for r in rows}


# -- orientation ---------------------------------------------------------------

def test_overview_describes_the_graph(t):
    o = t.call("overview")
    assert o["nodes_by_type"]["subdomain"] == 3
    assert ids(o["entry_points"]) == {"dom:example.com"}
    assert {"from": "subdomain", "edge": "has_endpoint", "to": "endpoint", "count": 5} \
        in o["how_types_connect"]
    assert all(lead["count"] > 0 for lead in o["leads"])
    assert any(lead["query"] == "type:endpoint code:401|403" for lead in o["leads"])
    assert o["recent_imports"][0]["tool"] == "nuclei"
    assert "key:value" in o["query_syntax"]


# -- node references -----------------------------------------------------------

@pytest.mark.parametrize("ref,expected", [
    ("sub:api.example.com", "sub:api.example.com"),
    ("api.example.com", "sub:api.example.com"),
    ("API.Example.COM.", "sub:api.example.com"),
    ("https://api.example.com/admin", "ep:api.example.com/admin"),
    ("api.example.com/admin/", "ep:api.example.com/admin"),
    ("203.0.113.10", "ip:203.0.113.10"),
    ("nginx", "tech:nginx"),
])
def test_resolve_accepts_ids_and_plain_values(t, ref, expected):
    assert t.resolve(ref).id == expected


def test_resolve_errors_name_the_fix(t, repo):
    with pytest.raises(ToolError, match="Closest: .*sub:api.example.com"):
        t.resolve("api.example")
    with pytest.raises(ToolError, match="no node"):
        t.resolve("nothing-like-this")
    _load(repo, program="acme")
    with pytest.raises(ToolError, match="matches 2 nodes.*acme::sub:api.example.com"):
        t.resolve("api.example.com")
    assert t.resolve("api.example.com", "acme").id == "acme::sub:api.example.com"
    assert AgentTools(repo, program="acme").resolve("sub:api.example.com").id == "sub:api.example.com"


# -- find ----------------------------------------------------------------------

def test_find_returns_compact_rows_and_pages(t):
    r = t.call("find", {"query": "type:endpoint", "limit": 2, "sort": "value", "order": "asc"})
    assert r["total"] == 5 and len(r["nodes"]) == 2
    assert "offset=2" in r["more"]
    row = next(n for n in t.call("find", {"query": "type:endpoint code:403"})["nodes"])
    assert row == {"id": "ep:api.example.com/admin", "type": "endpoint",
                   "value": "api.example.com/admin", "status_code": 403}
    last = t.call("find", {"query": "type:endpoint", "limit": 2, "offset": 4})
    assert len(last["nodes"]) == 1 and "more" not in last


def test_find_count_by(t):
    by_type = t.call("find", {"count_by": "type"})
    assert {"value": "endpoint", "count": 5} in by_type["groups"]
    codes = t.call("find", {"query": "type:endpoint", "count_by": "status_code"})
    assert codes["total"] == 5
    assert {g["value"]: g["count"] for g in codes["groups"]} == {200: 2, 403: 1, 500: 1, 302: 1}
    hosts = t.call("find", {"query": "type:endpoint|parameter", "count_by": "host"})
    assert {"value": "api.example.com", "count": 5} in hosts["groups"]
    tags = t.call("find", {"query": "type:finding", "count_by": "tag"})
    assert {"value": "exposure", "count": 1} in tags["groups"]


def test_find_rejects_bad_input_readably(t):
    with pytest.raises(ToolError, match="expected a number"):
        t.call("find", {"query": "links:>=many"})
    with pytest.raises(ToolError, match="does not take 'q'"):
        t.call("find", {"q": "x"})
    with pytest.raises(ToolError, match="unknown tool"):
        t.call("drop_everything")


# -- inspect / neighbors -------------------------------------------------------

def test_inspect_maps_relationships(t):
    r = t.call("inspect", {"node": "api.example.com", "sample": 2})
    rel = {(x["edge"], x["direction"], x["type"]): x for x in r["relationships"]}
    assert rel[("has_endpoint", "out", "endpoint")]["count"] == 3
    assert len(rel[("has_endpoint", "out", "endpoint")]["sample"]) == 2
    assert rel[("resolves_to", "out", "ip")]["count"] == 1
    assert rel[("subdomain_of", "out", "domain")]["sample"][0]["id"] == "dom:example.com"
    assert r["allowed_next_status"] == ["ignored", "in_scope", "out_of_scope"]
    assert "more" in r
    ep = t.call("inspect", {"node": "https://api.example.com/go", "sample": 0})
    assert ep["url"] == "https://api.example.com/go" and ep["props"]["status_code"] == 302
    assert all("sample" not in x for x in ep["relationships"]) and "more" not in ep


def test_neighbors_filters(t):
    r = t.call("neighbors", {"node": "api.example.com", "type": "endpoint"})
    assert r["total"] == 3 and all(n["edge"] == "has_endpoint" for n in r["neighbors"])
    r = t.call("neighbors", {"node": "api.example.com", "type": "endpoint", "query": "code:403"})
    assert ids(r["neighbors"]) == {"ep:api.example.com/admin"}
    r = t.call("neighbors", {"node": "203.0.113.10", "direction": "in", "edge": "resolves_to"})
    assert ids(r["neighbors"]) == {"sub:api.example.com", "sub:dev.example.com"}
    assert t.call("neighbors", {"node": "203.0.113.10", "direction": "out"})["total"] == 0
    r = t.call("neighbors", {"node": "api.example.com", "limit": 2})
    assert len(r["neighbors"]) == 2 and "offset=2" in r["more"]
    empty = t.call("neighbors", {"node": "api.example.com", "type": "certificate"})
    assert empty["total"] == 0 and "has_endpoint" in empty["hint"]
    with pytest.raises(ToolError, match="unknown node type 'host'"):
        t.call("neighbors", {"node": "api.example.com", "type": "host"})


# -- traverse / path -----------------------------------------------------------

def test_traverse_from_a_node(t):
    r = t.call("traverse", {"start": "203.0.113.10", "hops": ["subdomain", "endpoint"]})
    assert [s["nodes"] for s in r["steps"]] == [1, 2, 4]
    assert "ep:shop.example.com/" not in ids(r["nodes"])
    git = next(n for n in r["nodes"] if n["id"] == "ep:dev.example.com/.git/config")
    assert git["via"] == ["has_endpoint ← sub:dev.example.com", "resolves_to ← ip:203.0.113.10"]
    only200 = t.call("traverse", {"start": "203.0.113.10", "hops": ["subdomain", "endpoint"],
                                  "where": "code:200"})
    assert ids(only200["nodes"]) == {"ep:api.example.com/v2/users",
                                     "ep:dev.example.com/.git/config"}


def test_traverse_from_a_query_and_by_edge_type(t):
    r = t.call("traverse", {"start_query": "type:technology value:node.js",
                            "hops": ["subdomain", "endpoint", "parameter"]})
    assert {n["name"] for n in r["nodes"]} == {"redirect_uri", "q"}
    siblings = t.call("traverse", {"start": "api.example.com", "hops": ["resolves_to", "resolves_to"]})
    assert ids(siblings["nodes"]) == {"sub:dev.example.com"}      # never back to the start
    any_hop = t.call("traverse", {"start": "dev.example.com/.git/config", "hops": ["*"]})
    assert {n["type"] for n in any_hop["nodes"]} == {"subdomain", "finding"}
    dead = t.call("traverse", {"start": "example.com", "hops": ["certificate", "ip"]})
    assert dead["total"] == 0 and "hint" in dead and len(dead["steps"]) == 2


def test_traverse_validates(t):
    with pytest.raises(ToolError, match="unknown hop 'hosts'"):
        t.call("traverse", {"start": "example.com", "hops": ["hosts"]})
    with pytest.raises(ToolError, match="exactly one"):
        t.call("traverse", {"hops": ["subdomain"]})
    with pytest.raises(ToolError, match="1 to 6"):
        t.call("traverse", {"start": "example.com", "hops": []})


def test_path(t):
    r = t.call("path", {"source": "git-config @ https://dev.example.com/.git/config",
                        "target": "203.0.113.10"})
    assert r["found"] and r["length"] == 3
    assert [p["id"] for p in r["path"]] == [
        "finding:git-config @ https://dev.example.com/.git/config",
        "ep:dev.example.com/.git/config", "sub:dev.example.com", "ip:203.0.113.10"]
    assert [(p["edge"], p["direction"]) for p in r["path"][1:]] == [
        ("affects", "out"), ("has_endpoint", "in"), ("resolves_to", "out")]
    # api and shop share only nginx and the apex; technology is avoided by default
    via_apex = t.call("path", {"source": "api.example.com", "target": "shop.example.com"})
    assert [p["id"] for p in via_apex["path"]][1] == "dom:example.com"
    blocked = t.call("path", {"source": "api.example.com", "target": "shop.example.com",
                              "avoid": ["technology", "domain"]})
    assert not blocked["found"] and "avoid=[]" in blocked["hint"]
    via_tech = t.call("path", {"source": "api.example.com", "target": "PHP", "avoid": []})
    assert via_tech["found"] and via_tech["length"] == 3
    assert t.call("path", {"source": "nginx", "target": "tech:nginx"})["length"] == 0
    assert not t.call("path", {"source": "api.example.com", "target": "shop.example.com/",
                               "max_depth": 1})["found"]


# -- writes --------------------------------------------------------------------

def test_annotate_appends_and_respects_the_state_machine(t, repo):
    repo.update_node("sub:api.example.com", notes="human note")
    r = t.call("annotate", {"nodes": ["api.example.com", "ghost", "dev.example.com"],
                            "note": "auth looks weak", "add_tags": ["reviewed"],
                            "status": "in_scope"})
    assert r["updated"] == ["sub:api.example.com", "sub:dev.example.com"]
    assert r["skipped"][0]["node"] == "ghost"
    n = repo.get_node("sub:api.example.com")
    assert n.notes == "human note\n[agent] auth looks weak"
    assert n.status.value == "in_scope" and n.tags == ["reviewed"]
    bad = t.call("annotate", {"nodes": ["shop.example.com"], "status": "confirmed"})
    assert not bad["updated"] and "allowed: ignored, in_scope, out_of_scope" in bad["skipped"][0]["reason"]
    with pytest.raises(ToolError, match="nothing to do"):
        t.call("annotate", {"nodes": ["api.example.com"]})


def test_report_finding_links_and_marks_agent(t, repo):
    r = t.call("report_finding", {
        "title": "IDOR on user id", "affects": ["https://api.example.com/v2/users"],
        "severity": "high", "kind": "intuition", "confidence": 0.4, "note": "ids are sequential"})
    assert r["affects"] == ["ep:api.example.com/v2/users"]
    node = repo.get_node(r["finding"]["id"])
    assert node.author_type.value == "agent" and node.props["severity"] == "high"
    back = t.call("neighbors", {"node": "api.example.com/v2/users", "type": "finding"})
    assert ids(back["neighbors"]) == {r["finding"]["id"]}
    assert t.call("find", {"query": "type:finding author:agent"})["total"] == 1
    with pytest.raises(ToolError, match="unknown severity"):
        t.call("report_finding", {"title": "x", "severity": "urgent"})
    with pytest.raises(ToolError, match="no node"):
        t.call("report_finding", {"title": "x", "affects": ["ghost"]})


def test_read_only_hides_and_refuses_writes(repo):
    ro = AgentTools(repo, read_only=True)
    assert [s["name"] for s in ro.specs()] == [
        "overview", "find", "inspect", "neighbors", "traverse", "path"]
    with pytest.raises(ToolError, match="unknown tool"):
        ro.call("annotate", {"nodes": ["api.example.com"], "note": "x"})


def test_program_scoping(repo):
    _load(repo, program="acme")
    acme = AgentTools(repo, program="acme")
    assert acme.call("overview")["total_nodes"] == AgentTools(repo).call("overview")["total_nodes"] // 2
    r = acme.call("traverse", {"start": "203.0.113.10", "hops": ["subdomain"]})
    assert ids(r["nodes"]) == {"acme::sub:api.example.com", "acme::sub:dev.example.com"}
    f = acme.call("report_finding", {"title": "hunch", "affects": ["api.example.com"]})
    assert f["finding"]["id"].startswith("acme::")


def test_long_values_are_clipped(t, repo):
    repo.update_node("sub:api.example.com", props={"body": "A" * 5000, "many": list(range(100))})
    r = t.call("inspect", {"node": "api.example.com", "sample": 0})
    assert len(r["props"]["body"]) < 500 and "+4600 chars" in r["props"]["body"]
    assert len(r["props"]["many"]) == 31


# -- MCP -----------------------------------------------------------------------

def rpc(method, params=None, id=1):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return msg


def test_mcp_handshake_and_tool_listing(t):
    s = McpServer(t)
    init = s.handle(rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                      "clientInfo": {"name": "x", "version": "1"}}))["result"]
    assert init["protocolVersion"] == "2025-03-26" and "tools" in init["capabilities"]
    assert init["serverInfo"]["name"] == "rainman" and "untrusted" in init["instructions"]
    assert s.handle(rpc("initialize", {"protocolVersion": "1999-01-01"}))["result"][
        "protocolVersion"] == "2025-11-25"
    assert s.handle(rpc("notifications/initialized", id=None)) is None
    assert s.handle(rpc("ping")) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    tools = s.handle(rpc("tools/list"))["result"]["tools"]
    assert [x["name"] for x in tools] == ["overview", "find", "inspect", "neighbors",
                                          "traverse", "path", "annotate", "report_finding"]
    for x in tools:
        assert x["inputSchema"]["type"] == "object" and x["description"]
        assert set(x["inputSchema"]["required"]) <= set(x["inputSchema"]["properties"])
    assert {x["name"] for x in tools if not x["annotations"]["readOnlyHint"]} == {
        "annotate", "report_finding"}


def test_mcp_tool_calls_and_errors(t):
    s = McpServer(t)
    ok = s.handle(rpc("tools/call", {"name": "find", "arguments": {"query": "type:ip"}}))["result"]
    assert ok["isError"] is False
    assert json.loads(ok["content"][0]["text"])["total"] == 2
    bad = s.handle(rpc("tools/call", {"name": "inspect", "arguments": {"node": "ghost"}}))["result"]
    assert bad["isError"] is True and "no node" in bad["content"][0]["text"]
    missing = s.handle(rpc("tools/call", {"name": "inspect", "arguments": {}}))["result"]
    assert missing["isError"] and "needs node" in missing["content"][0]["text"]
    assert s.handle(rpc("nope/nope"))["error"]["code"] == -32601
    assert s.handle({"id": 3})["error"]["code"] == -32600
    assert s.handle(rpc("tools/call", [1]))["error"]["code"] == -32602
    assert s.handle(rpc("resources/list"))["result"] == {"resources": []}
    assert s.handle({"jsonrpc": "2.0", "id": 9, "result": {}}) is None


def test_mcp_stdio_loop(t):
    lines = [json.dumps(rpc("initialize", {"protocolVersion": "2025-06-18"}, id=1)),
             json.dumps(rpc("notifications/initialized", id=None)), "", "{not json",
             json.dumps(rpc("tools/call", {"name": "path", "arguments": {
                 "source": "api.example.com", "target": "203.0.113.10"}}, id="b"))]
    out = io.StringIO()
    McpServer(t).serve_stdio(io.StringIO("\n".join(lines) + "\n"), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r.get("id") for r in replies] == [1, None, "b"]
    assert replies[1]["error"]["code"] == -32700
    assert json.loads(replies[2]["result"]["content"][0]["text"])["length"] == 1


def test_mcp_over_http(tmp_path):
    db = str(tmp_path / "g.db")
    repo = SqliteGraphRepository(db)
    _load(repo)
    repo.close()
    c = TestClient(create_app(db))
    r = c.post("/mcp", json=rpc("tools/call", {"name": "inspect", "arguments": {"node": "nginx"}}))
    assert r.status_code == 200
    assert json.loads(r.json()["result"]["content"][0]["text"])["id"] == "tech:nginx"
    assert c.post("/mcp", json=rpc("notifications/initialized", id=None)).status_code == 202
    batch = c.post("/mcp", json=[rpc("ping", id=1), rpc("tools/list", id=2)]).json()
    assert [b["id"] for b in batch] == [1, 2]
    assert c.post("/mcp", content="{", headers={"content-type": "application/json"}).status_code == 400
    assert c.get("/mcp").status_code == 405
    # a web page must not be able to drive the tools
    evil = c.post("/mcp", json=rpc("tools/list"), headers={"origin": "https://evil.example"})
    assert evil.status_code == 403
    ro = TestClient(create_app(db, agent_read_only=True))
    names = [x["name"] for x in ro.post("/mcp", json=rpc("tools/list")).json()["result"]["tools"]]
    assert "annotate" not in names and "find" in names


def test_cli_call(tmp_path, capsys):
    db = str(tmp_path / "g.db")
    repo = SqliteGraphRepository(db)
    _load(repo)
    repo.close()
    assert main(["--db", db, "call"]) == 0
    assert "traverse(hops, [start]" in capsys.readouterr().out
    assert main(["--db", db, "call", "neighbors",
                 '{"node": "api.example.com", "type": "ip"}', "--compact"]) == 0
    assert json.loads(capsys.readouterr().out)["neighbors"][0]["id"] == "ip:203.0.113.10"
    assert main(["--db", db, "call", "inspect", '{"node": "ghost"}']) == 1
    assert "no node" in capsys.readouterr().err
    assert main(["--db", db, "call", "find", "not json"]) == 2
    assert main(["--db", db, "call", "--read-only", "annotate", '{"nodes": ["x"], "note": "n"}']) == 1
