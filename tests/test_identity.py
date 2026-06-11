from rainman.domain.identity import make_id, normalize_url, normalize_host
from rainman.domain.model import NodeType


def test_host_normalization_dedupes():
    assert make_id(NodeType.subdomain, "API.Example.com.") == make_id(
        NodeType.subdomain, "api.example.com"
    )


def test_url_drops_default_port_and_query():
    a = normalize_url("https://api.example.com:443/v2/users?id=1")
    b = normalize_url("https://api.example.com/v2/users")
    assert a == b == "api.example.com/v2/users"


def test_url_keeps_nonstandard_port():
    assert normalize_url("http://h.example.com:8080/x/") == "h.example.com:8080/x"


def test_root_path_preserved():
    assert normalize_url("https://example.com") == "example.com/"
