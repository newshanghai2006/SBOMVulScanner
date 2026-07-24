import asyncio
import json

import httpx

from app.models import Component
from app.scanner import _fixed_version, _score_vector, query_osv_batch


def test_cvss_vector_score():
    assert _score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_osv_batch_parses_alias_score_and_fix():
    component = Component(name="demo", version="1.0", purl="pkg:pypi/demo@1.0")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            assert json.loads(request.content) == {"queries": [{"package": {"purl": "pkg:pypi/demo@1.0"}}]}
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-demo"}]}]})
        if request.url.path == "/v1/vulns/GHSA-demo":
            return httpx.Response(200, json={
                "id": "GHSA-demo", "aliases": ["CVE-2026-0001"], "summary": "Example",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"purl": "pkg:pypi/demo"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}],
            })
        raise AssertionError(f"Unexpected request: {request.url}")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await query_osv_batch(client, [component])

    result = asyncio.run(run())[0]
    assert result.status == "vulnerable"
    assert result.vulnerabilities[0].id == "CVE-2026-0001"
    assert result.vulnerabilities[0].aliases == ["CVE-2026-0001", "GHSA-demo"]
    assert result.vulnerabilities[0].score == 9.8
    assert result.vulnerabilities[0].fixed_version == "1.1"


def test_osv_batch_failure_is_not_reported_as_clean():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await query_osv_batch(client, [Component(name="demo", version="1", purl="pkg:pypi/demo@1")])

    assert asyncio.run(run())[0].status == "error"


def test_osv_batch_retries_transient_connect_timeout():
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectTimeout("temporary network failure", request=request)
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await query_osv_batch(client, [Component(name="demo", version="1", purl="pkg:pypi/demo@1")])

    assert asyncio.run(run())[0].status == "clean"
    assert attempts == 2


def test_fix_version_comes_from_installed_versions_range():
    vuln = {"affected": [{
        "package": {"purl": "pkg:npm/rollup"},
        "ranges": [{"events": [
            {"introduced": "0"}, {"fixed": "2.80.0"},
            {"introduced": "4.0.0"}, {"fixed": "4.60.0"},
        ]}],
    }]}
    component = Component(name="rollup", version="4.55.3", purl="pkg:npm/rollup@4.55.3")
    assert _fixed_version(vuln, component) == "4.60.0"
