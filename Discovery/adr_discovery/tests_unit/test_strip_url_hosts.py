"""strip_url must return a URL that still parses, or the redaction marker.

An IPv6 host without its brackets reads back as a host plus a bogus port,
and an unparseable port must not escape as an exception that drops the
whole record.
"""

from __future__ import annotations

import pytest

from adr_discovery.contracts.records import Candidate
from adr_discovery.extractor import extract
from adr_discovery.redact.rules import REDACTED, strip_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://[::1]:8080/mcp", "http://[::1]:8080/mcp"),
        ("https://user:pw@[2001:db8::1]/p?q=1#f", "https://[2001:db8::1]/p"),
        ("https://user:pw@example.com:8443/p?q=1", "https://example.com:8443/p"),
    ],
)
def test_hosts_and_ports_survive(url, expected):
    assert strip_url(url) == expected
    assert strip_url(strip_url(url)) == expected


@pytest.mark.parametrize("url", ["http://localhost:${PORT}/mcp", "http://h:99999/"])
def test_an_unparseable_port_is_redacted_not_raised(url):
    assert strip_url(url) == REDACTED


def test_ipv6_and_templated_servers_are_declared_not_errors(world):
    world.json("/proj/.mcp.json", {"mcpServers": {
        "v6": {"url": "http://[::1]:8080/mcp"},
        "templated": {"url": "http://localhost:${PORT}/mcp"},
    }})

    result = extract(world.gate(), Candidate("marker_file", "/proj/.mcp.json", "sweep"))

    assert result.errors == ()
    urls = {d.name: d.url for d in result.declarations}
    assert urls == {"v6": "http://[::1]:8080/mcp", "templated": REDACTED}


def test_judge_reads_the_whole_ipv6_host_as_the_destination():
    from adr_discovery.contracts.evidence import Band, Channel
    from adr_discovery.contracts.records import Asset, Declaration, Kind
    from adr_discovery.judge import judge

    asset = Asset(asset_id="id-v6", kind=Kind.MCP_SERVER, name="v6", identity="v6",
                  catalog_id="v6", confidence=Band("medium", (Channel.CONFIG,)))
    decl = Declaration(kind=Kind.MCP_SERVER, name="v6", path="/cfg", url="http://[::1]:8080/mcp")

    judged, _ = judge((asset,), {"id-v6": decl})

    assert judged[0].risk.destinations == ("::1",)
