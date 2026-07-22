from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

import httpx
from cvss import CVSS2, CVSS3, CVSS4
from univers import versions as univers_versions

from .models import Component, ComponentResult, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index:index + size]


def _severity(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _score_vector(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        if vector.startswith("CVSS:2") or vector.startswith("AV:"):
            return float(CVSS2(vector.removeprefix("CVSS:2.0/")).base_score)
    except (ValueError, TypeError, IndexError):
        return None
    return None


def _osv_score(vuln: dict[str, Any]) -> float | None:
    scores = [_score_vector(item.get("score", "")) for item in vuln.get("severity", [])]
    valid = [score for score in scores if score is not None]
    return max(valid) if valid else None


def _cvss_score(metrics: dict[str, Any]) -> float | None:
    scores = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []):
            score = entry.get("cvssData", {}).get("baseScore")
            if score is not None:
                scores.append(float(score))
    return max(scores) if scores else None


def _canonical_id(vuln_id: str, aliases: list[str]) -> str:
    all_ids = [vuln_id, *aliases]
    return next((item for item in all_ids if item.startswith("CVE-")), vuln_id)


VERSION_CLASSES = {
    "pypi": univers_versions.PypiVersion,
    "npm": univers_versions.SemverVersion,
    "maven": univers_versions.MavenVersion,
    "golang": univers_versions.GolangVersion,
    "go": univers_versions.GolangVersion,
    "cargo": univers_versions.SemverVersion,
    "nuget": univers_versions.NugetVersion,
    "gem": univers_versions.RubygemsVersion,
    "composer": univers_versions.ComposerVersion,
    "deb": univers_versions.DebianVersion,
    "rpm": univers_versions.RpmVersion,
    "apk": univers_versions.AlpineLinuxVersion,
}


def _version_class(component: Component):
    purl_type = component.purl.removeprefix("pkg:").split("/", 1)[0].lower() if component.purl else ""
    return VERSION_CLASSES.get(purl_type) or VERSION_CLASSES.get((component.ecosystem or "").lower())


def _parse_version(version_class, value: str):
    try:
        return version_class(value)
    except (ValueError, TypeError):
        return None


def _range_fix(events: list[dict[str, Any]], installed: str, version_class) -> str | None:
    current = _parse_version(version_class, installed)
    if current is None:
        return None
    active = False
    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
            start = None if introduced == "0" else _parse_version(version_class, introduced)
            active = start is None or current >= start
        elif "fixed" in event:
            fixed_text = str(event["fixed"])
            fixed = _parse_version(version_class, fixed_text)
            if active and fixed is not None and current < fixed:
                return fixed_text
            active = False
        elif "last_affected" in event:
            last = _parse_version(version_class, str(event["last_affected"]))
            active = active and last is not None and current <= last
            if active:
                return None
            active = False
        elif "limit" in event:
            limit = _parse_version(version_class, str(event["limit"]))
            if active and limit is not None and current < limit:
                return None
            active = False
    return None


def _fixed_version(vuln: dict[str, Any], component: Component) -> str | None:
    if not component.version:
        return None
    version_class = _version_class(component)
    if version_class is None:
        return None
    candidates: list[str] = []
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        package_purl = package.get("purl")
        package_name = package.get("name")
        if component.purl and package_purl and component.purl.split("@", 1)[0] != package_purl.split("@", 1)[0]:
            continue
        if not component.purl and package_name and package_name != component.name:
            continue
        for version_range in affected.get("ranges", []):
            fixed = _range_fix(version_range.get("events", []), component.version, version_class)
            if fixed:
                candidates.append(fixed)
    parsed = [(candidate, _parse_version(version_class, candidate)) for candidate in candidates]
    valid = [(text, version) for text, version in parsed if version is not None]
    return min(valid, key=lambda item: item[1])[0] if valid else None


def _osv_query(component: Component) -> dict[str, Any]:
    if component.purl:
        query: dict[str, Any] = {"package": {"purl": component.purl}}
        if component.version and "@" not in component.purl:
            query["version"] = component.version
        return query
    return {"package": {"name": component.name, "ecosystem": component.ecosystem}, "version": component.version}


def _from_osv(vuln: dict[str, Any], component: Component) -> Vulnerability:
    raw_id = vuln.get("id", "UNKNOWN")
    aliases = sorted(set(vuln.get("aliases", [])) | {raw_id})
    score = _osv_score(vuln)
    return Vulnerability(
        id=_canonical_id(raw_id, aliases), aliases=aliases, summary=vuln.get("summary", ""),
        severity=_severity(score), score=score, fixed_version=_fixed_version(vuln, component),
        published=vuln.get("published"), modified=vuln.get("modified"),
        references=[ref["url"] for ref in vuln.get("references", []) if ref.get("url")][:5], source="OSV",
    )


async def scan_components(components: list[Component], nvd_api_key: str | None = None) -> list[ComponentResult]:
    headers = {"User-Agent": "SBOM-Scan/2.0"}
    limits = httpx.Limits(max_connections=12, max_keepalive_connections=6)
    async with httpx.AsyncClient(timeout=30, headers=headers, limits=limits) as client:
        results: list[ComponentResult | None] = [None] * len(components)
        software_indices = [i for i, component in enumerate(components) if component.purl or (component.ecosystem and component.version)]
        nvd_indices = [i for i, component in enumerate(components) if i not in software_indices and component.cpe]
        unknown_indices = [i for i in range(len(components)) if i not in software_indices and i not in nvd_indices]

        if software_indices:
            software_results = await query_osv_batch(client, [components[i] for i in software_indices])
            for index, result in zip(software_indices, software_results, strict=True):
                results[index] = result

        nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
        semaphore = asyncio.Semaphore(5 if nvd_api_key else 2)

        async def guarded(index: int) -> tuple[int, ComponentResult]:
            async with semaphore:
                return index, await _safe_nvd(client, components[index], nvd_headers)

        for index, result in await asyncio.gather(*(guarded(i) for i in nvd_indices)):
            results[index] = result
        for index in unknown_indices:
            results[index] = ComponentResult(component=components[index], status="unknown", message="Missing purl/CPE; reliable matching is not possible")

        completed = [result for result in results if result is not None]
        await enrich_risk(client, completed)
        for result in completed:
            result.vulnerabilities.sort(key=lambda vuln: (not vuln.kev, SEVERITY_ORDER.get(vuln.severity, 4), -(vuln.epss or 0), vuln.id))
        return completed


async def query_osv_batch(client: httpx.AsyncClient, components: list[Component]) -> list[ComponentResult]:
    try:
        response = await client.post(OSV_BATCH_URL, json={"queries": [_osv_query(component) for component in components]})
        response.raise_for_status()
        batch_results = response.json().get("results", [])
        if len(batch_results) != len(components):
            raise ValueError("OSV batch response length mismatch")

        vuln_ids = sorted({item["id"] for result in batch_results for item in result.get("vulns", []) if item.get("id")})
        semaphore = asyncio.Semaphore(10)

        async def fetch(vuln_id: str) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                detail = await client.get(OSV_VULN_URL.format(vuln_id=vuln_id))
                detail.raise_for_status()
                return vuln_id, detail.json()

        details = dict(await asyncio.gather(*(fetch(vuln_id) for vuln_id in vuln_ids)))
        output = []
        for component, matched in zip(components, batch_results, strict=True):
            vulnerabilities = [_from_osv(details[item["id"]], component) for item in matched.get("vulns", []) if item.get("id") in details]
            output.append(ComponentResult(component=component, vulnerabilities=vulnerabilities, status="vulnerable" if vulnerabilities else "clean"))
        return output
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return [ComponentResult(component=component, status="error", message=f"OSV query failed: {type(exc).__name__}") for component in components]


async def _safe_nvd(client: httpx.AsyncClient, component: Component, headers: dict[str, str]) -> ComponentResult:
    try:
        return await query_nvd(client, component, headers)
    except httpx.HTTPStatusError as exc:
        return ComponentResult(component=component, status="error", message=f"NVD returned HTTP {exc.response.status_code}")
    except httpx.HTTPError as exc:
        return ComponentResult(component=component, status="error", message=f"NVD connection failed: {exc}")


async def query_nvd(client: httpx.AsyncClient, component: Component, headers: dict[str, str] | None = None) -> ComponentResult:
    response = await client.get(NVD_URL, params={"cpeName": component.cpe, "resultsPerPage": 200}, headers=headers)
    response.raise_for_status()
    vulnerabilities = []
    for entry in response.json().get("vulnerabilities", []):
        cve = entry.get("cve", {})
        descriptions = cve.get("descriptions", [])
        summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        score = _cvss_score(cve.get("metrics", {}))
        cve_id = cve.get("id", "UNKNOWN")
        vulnerabilities.append(Vulnerability(
            id=cve_id, aliases=[cve_id], summary=summary, severity=_severity(score), score=score,
            published=cve.get("published"), modified=cve.get("lastModified"),
            references=[ref["url"] for ref in cve.get("references", []) if ref.get("url")][:5], source="NVD",
        ))
    return ComponentResult(component=component, vulnerabilities=vulnerabilities, status="vulnerable" if vulnerabilities else "clean")


async def enrich_risk(client: httpx.AsyncClient, results: list[ComponentResult]) -> None:
    cve_ids = sorted({vuln.id for result in results for vuln in result.vulnerabilities if vuln.id.startswith("CVE-")})
    if not cve_ids:
        return
    epss: dict[str, tuple[float, float]] = {}
    kev: set[str] = set()

    async def fetch_epss() -> None:
        for chunk in _chunks(cve_ids, 100):
            try:
                response = await client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                response.raise_for_status()
                for item in response.json().get("data", []):
                    epss[item["cve"]] = (float(item["epss"]), float(item["percentile"]))
            except (httpx.HTTPError, ValueError, KeyError):
                continue

    async def fetch_kev() -> None:
        try:
            response = await client.get(KEV_URL)
            response.raise_for_status()
            kev.update(item["cveID"] for item in response.json().get("vulnerabilities", []) if item.get("cveID"))
        except (httpx.HTTPError, ValueError, KeyError):
            return

    await asyncio.gather(fetch_epss(), fetch_kev())
    for result in results:
        deduped: dict[str, Vulnerability] = {}
        for vuln in result.vulnerabilities:
            key = vuln.id
            if key in epss:
                vuln.epss, vuln.epss_percentile = epss[key]
            vuln.kev = key in kev
            existing = deduped.get(key)
            if existing:
                existing.aliases = sorted(set(existing.aliases + vuln.aliases))
                existing.references = list(dict.fromkeys(existing.references + vuln.references))[:5]
                if (vuln.score or 0) > (existing.score or 0):
                    existing.score, existing.severity = vuln.score, vuln.severity
                existing.fixed_version = existing.fixed_version or vuln.fixed_version
            else:
                deduped[key] = vuln
        result.vulnerabilities = list(deduped.values())
