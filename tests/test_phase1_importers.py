import pytest

from rainman.adapters.importers import available, get_importer
from rainman.adapters.importers.base import param_key
from rainman.adapters.store import SqliteGraphRepository
from rainman.domain.identity import make_id
from rainman.domain.ingest import IngestService
from rainman.domain.model import NodeType


@pytest.fixture
def svc():
    repo = SqliteGraphRepository(":memory:")
    yield IngestService(repo), repo
    repo.close()


def test_all_phase1_importers_registered():
    expected = {
        "httpx", "dnsx", "nmap", "naabu", "shuffledns", "subfinder", "katana",
        "gau", "waybackurls", "ffuf", "kiterunner", "x8",
    }
    assert expected <= set(available())


def test_subfinder_uses_input_as_apex(svc):
    s, repo = svc
    raw = (
        '{"host":"cdn.memoryleaks.ir","input":"memoryleaks.ir","source":"submd"}\n'
        '{"host":"test.memoryleaks.ir","input":"memoryleaks.ir","source":"rapiddns"}'
    )
    s.ingest(get_importer("subfinder").parse(raw))
    _, subs = repo.neighbors(make_id(NodeType.domain, "memoryleaks.ir"), types=["subdomain"])
    assert {n.value for n in subs} == {"cdn.memoryleaks.ir", "test.memoryleaks.ir"}
    cdn = repo.get_node(make_id(NodeType.subdomain, "cdn.memoryleaks.ir"))
    assert cdn.props["discovered_via"] == "submd"


NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="203.0.113.10" addrtype="ipv4"/>
<hostnames><hostname name="api.example.com" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.25"/></port>
</ports></host></nmaprun>"""


def test_nmap_service_and_ip(svc):
    s, repo = svc
    s.ingest(get_importer("nmap").parse(NMAP_XML))
    svc_id = make_id(NodeType.service, "203.0.113.10:443/tcp")
    node = repo.get_node(svc_id)
    assert node.props["product"] == "nginx"
    assert node.props["port"] == 443
    _, neigh = repo.neighbors("ip:203.0.113.10")
    assert any(n.type == NodeType.service for n in neigh)


def test_naabu_then_nmap_share_service_node(svc):
    s, repo = svc
    s.ingest(get_importer("naabu").parse('{"host":"api.example.com","ip":"203.0.113.10","port":443,"protocol":"tcp"}'))
    s.ingest(get_importer("nmap").parse(NMAP_XML))
    node = repo.get_node(make_id(NodeType.service, "203.0.113.10:443/tcp"))
    assert set(node.sources) == {"naabu", "nmap"}
    assert node.props["product"] == "nginx"  # nmap enriched the naabu node


def test_shuffledns_subdomain_of(svc):
    s, repo = svc
    s.ingest(get_importer("shuffledns").parse("api.example.com\nadmin.example.co.uk\n"))
    _, neigh = repo.neighbors(make_id(NodeType.subdomain, "api.example.com"))
    assert any(n.value == "example.com" for n in neigh)
    # multi-label suffix handled
    assert repo.get_node(make_id(NodeType.domain, "example.co.uk")) is not None


def test_katana_params_and_js_tag(svc):
    s, repo = svc
    rec = '{"request":{"endpoint":"https://api.example.com/v2/users?id=1","method":"GET","source":"https://api.example.com/app.js"},"response":{"status_code":200}}'
    s.ingest(get_importer("katana").parse(rec))
    ep = repo.get_node(make_id(NodeType.endpoint, "https://api.example.com/v2/users?id=1"))
    assert "js-sourced" in ep.tags
    param = repo.get_node(make_id(NodeType.parameter, param_key("https://api.example.com/v2/users", "id")))
    assert param.props["name"] == "id"


def test_gau_and_waybackurls_dedupe(svc):
    s, repo = svc
    s.ingest(get_importer("gau").parse("https://api.example.com/old?q=1\n"))
    before = repo.digest()["total_nodes"]
    s.ingest(get_importer("waybackurls").parse("https://api.example.com/old?q=1\n"))
    assert repo.digest()["total_nodes"] == before
    ep = repo.get_node(make_id(NodeType.endpoint, "https://api.example.com/old"))
    assert set(ep.sources) == {"gau", "waybackurls"}


def test_ffuf_content_discovery(svc):
    s, repo = svc
    raw = '{"config":{"url":"https://api.example.com/FUZZ"},"results":[{"url":"https://api.example.com/admin","status":200,"length":12}]}'
    s.ingest(get_importer("ffuf").parse(raw))
    ep = repo.get_node(make_id(NodeType.endpoint, "https://api.example.com/admin"))
    assert ep.props["status_code"] == 200
    assert "content-discovery" in ep.tags


def test_x8_reflected_param(svc):
    s, repo = svc
    raw = '{"url":"https://api.example.com/search","found_params":[{"name":"q","location":"query","reflected":true}]}'
    s.ingest(get_importer("x8").parse(raw))
    p = repo.get_node(make_id(NodeType.parameter, param_key("https://api.example.com/search", "q")))
    assert p.props["reflected"] is True
    assert p.props["location"] == "query"


def test_kiterunner_api_tag(svc):
    s, repo = svc
    s.ingest(get_importer("kiterunner").parse('{"url":"https://api.example.com/v1/admin","status":200,"length":5}'))
    ep = repo.get_node(make_id(NodeType.endpoint, "https://api.example.com/v1/admin"))
    assert ep.props.get("kind") == "api"
