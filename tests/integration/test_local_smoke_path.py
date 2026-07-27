"""Offline contract tests for the explicitly constrained local smoke path."""

import json
from ipaddress import IPv4Address

import pytest  # type: ignore[reportMissingImports]

from redforge.adapters import (
    HTTPX_TOOL_ID,
    KATANA_TOOL_ID,
    SUBFINDER_TOOL_ID,
    WHATWEB_TOOL_ID,
    HttpxProbeProvider,
    KatanaWebCrawlProvider,
    LocalSeedSubdomainProvider,
    LocalStaticHostResolver,
    WhatWebTechnologyDetectionProvider,
)
from redforge.application import ScanConfig
from redforge.composition import ApplicationComposition, CompositionProfile
from redforge.domain import Endpoint, ExactNetworkTarget, Host
from redforge.sdk import ToolExecutionResult, ToolExecutionStatus, ToolId
from redforge.sdk.state import PipelineStateKey
from redforge.testing import FakeToolRunner

_URL = "http://lab.redforge.test:8080"
_HOSTNAME = "lab.redforge.test"
_IP = "127.0.0.1"


def _target() -> ExactNetworkTarget:
    return ExactNetworkTarget(_URL, expected_ip=_IP)


def _host(
    hostname: str = _HOSTNAME,
    address: str = _IP,
) -> Host:
    return Host(hostname=hostname, address=IPv4Address(address))


def _result(tool_id: ToolId, stdout: str) -> ToolExecutionResult:
    return ToolExecutionResult(
        tool_id=tool_id,
        status=ToolExecutionStatus.SUCCESS,
        exit_code=0,
        stdout=stdout,
        stderr="",
        duration_seconds=0,
    )


def test_exact_target_and_network_free_seed_providers() -> None:
    target = _target()
    discovery = LocalSeedSubdomainProvider(target)
    resolver = LocalStaticHostResolver(target)

    assert target.value == _URL
    assert target.scheme == "http"
    assert target.hostname == _HOSTNAME
    assert target.port == 8080
    assert target.expected_ip == _IP
    assert discovery.discover(_URL).hostnames == (_HOSTNAME,)
    assert resolver.resolve(_HOSTNAME) == (_IP,)
    assert not hasattr(discovery, "runner")
    assert not hasattr(resolver, "runner")


@pytest.mark.parametrize(
    "value",
    (
        "https://lab.redforge.test:8080",
        "http://other.redforge.test:8080",
        "http://lab.redforge.test:80",
        "http://lab.redforge.test:443",
    ),
)
def test_exact_target_rejects_changed_origin(value: str) -> None:
    candidate = ExactNetworkTarget(value, expected_ip=_IP)
    assert candidate != _target()


def test_exact_target_requires_an_explicit_port() -> None:
    with pytest.raises(ValueError, match="invalid"):
        ExactNetworkTarget(
            "http://lab.redforge.test",
            expected_ip=_IP,
        )


def test_external_adapters_receive_only_the_exact_origin() -> None:
    target = _target()
    runner = FakeToolRunner()
    runner.add_result(
        HTTPX_TOOL_ID,
        _result(
            HTTPX_TOOL_ID,
            json.dumps(
                {
                    "url": _URL,
                    "status_code": 200,
                    "host_ip": _IP,
                }
            ),
        ),
    )
    runner.add_result(
        KATANA_TOOL_ID,
        _result(
            KATANA_TOOL_ID,
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": f"{_URL}/page.html",
                    }
                }
            ),
        ),
    )
    runner.add_result(
        WHATWEB_TOOL_ID,
        _result(
            WHATWEB_TOOL_ID,
            json.dumps(
                [
                    {
                        "target": _URL,
                        "plugins": {
                            "Python HTTP Server": {"certainty": 100}
                        },
                    }
                ]
            ),
        ),
    )

    http = HttpxProbeProvider(runner=runner, exact_target=target)
    crawl = KatanaWebCrawlProvider(runner=runner, exact_target=target)
    detect = WhatWebTechnologyDetectionProvider(
        runner=runner,
        exact_target=target,
    )
    probe_result = http.probe((_host(),))
    crawl_result = crawl.crawl((_host(),))
    technology_result = detect.detect(
        (Endpoint(_HOSTNAME, 8080, "http", "/page.html"),)
    )

    assert probe_result.endpoints[0].url == _URL
    assert crawl_result.endpoints == (
        Endpoint(_HOSTNAME, 8080, "http", "/page.html"),
    )
    assert technology_result.technologies
    assert tuple(item.tool_id for item in runner.invocations) == (
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    assert runner.invocations[0].stdin == f"{_URL}\n"
    assert runner.invocations[1].stdin == f"{_URL}\n"
    assert "-disable-redirects" in runner.invocations[1].arguments
    scope_index = runner.invocations[1].arguments.index("-crawl-scope")
    assert runner.invocations[1].arguments[scope_index + 1] == (
        r"^http://lab\.redforge\.test:8080(?:/|$)"
    )
    assert runner.invocations[2].arguments[-1] == _URL
    serialized = repr(runner.invocations)
    assert "https://" not in serialized
    assert ":80/" not in serialized
    assert ":443/" not in serialized


@pytest.mark.parametrize(
    ("provider_name", "host"),
    (
        ("httpx", _host("other.redforge.test")),
        ("httpx", _host(address="127.0.0.2")),
        ("katana", _host("other.redforge.test")),
        ("katana", _host(address="127.0.0.2")),
    ),
)
def test_external_invocations_fail_closed_before_runner(
    provider_name: str,
    host: Host,
) -> None:
    runner = FakeToolRunner()
    if provider_name == "httpx":
        result = HttpxProbeProvider(
            runner=runner,
            exact_target=_target(),
        ).probe((host,))
    else:
        result = KatanaWebCrawlProvider(
            runner=runner,
            exact_target=_target(),
        ).crawl((host,))

    assert result.status.value == "error"
    assert runner.invocations == ()


def test_out_of_origin_tool_evidence_is_rejected() -> None:
    runner = FakeToolRunner()
    runner.add_result(
        HTTPX_TOOL_ID,
        _result(
            HTTPX_TOOL_ID,
            json.dumps(
                {
                    "url": _URL,
                    "status_code": 302,
                    "location": "http://attacker.test:8080/",
                }
            ),
        ),
    )
    runner.add_result(
        KATANA_TOOL_ID,
        _result(
            KATANA_TOOL_ID,
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": "https://lab.redforge.test:8080/",
                    }
                }
            ),
        ),
    )

    http = HttpxProbeProvider(runner=runner, exact_target=_target())
    crawl = KatanaWebCrawlProvider(runner=runner, exact_target=_target())

    assert not http.probe((_host(),)).endpoints
    assert not crawl.crawl((_host(),)).endpoints


def test_local_smoke_composition_runs_deterministically_offline() -> None:
    runner = FakeToolRunner()
    runner.add_result(
        HTTPX_TOOL_ID,
        _result(
            HTTPX_TOOL_ID,
            json.dumps(
                {
                    "url": _URL,
                    "status_code": 200,
                    "host_ip": _IP,
                }
            ),
        ),
    )
    runner.add_result(
        KATANA_TOOL_ID,
        _result(
            KATANA_TOOL_ID,
            "\n".join(
                (
                    json.dumps(
                        {
                            "request": {
                                "method": "GET",
                                "endpoint": f"{_URL}/",
                            }
                        }
                    ),
                    json.dumps(
                        {
                            "request": {
                                "method": "GET",
                                "endpoint": f"{_URL}/page.html",
                            }
                        }
                    ),
                )
            ),
        ),
    )
    runner.add_result(
        WHATWEB_TOOL_ID,
        _result(
            WHATWEB_TOOL_ID,
            json.dumps(
                [
                    {
                        "target": _URL,
                        "plugins": {
                            "Python HTTP Server": {"certainty": 100}
                        },
                    }
                ]
            ),
        ),
    )
    target = _target()
    composition = ApplicationComposition(
        CompositionProfile.LOCAL_SMOKE,
        tool_runner=runner,
        exact_target=target,
    )

    result = composition.create_orchestrator().run(
        ScanConfig.for_local_smoke(target)
    )

    assert result.accepted
    assert result.final_context.target_id == _URL
    assert result.final_context.state[PipelineStateKey.ENDPOINTS] == (
        Endpoint(_HOSTNAME, 8080, "http", "/"),
        Endpoint(_HOSTNAME, 8080, "http", "/page.html"),
    )
    assert tuple(item.tool_id for item in runner.invocations) == (
        HTTPX_TOOL_ID,
        KATANA_TOOL_ID,
        WHATWEB_TOOL_ID,
    )
    assert SUBFINDER_TOOL_ID not in tuple(
        item.tool_id for item in runner.invocations
    )
    capability_ids = tuple(
        item.capability_id for item in result.execution_history
    )
    assert all(item is not None for item in capability_ids)
    assert tuple(str(item) for item in capability_ids) == (
        "subdomain_discovery",
        "host_resolution",
        "http_probe",
        "web_crawl",
        "technology_detection",
    )
