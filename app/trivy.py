from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .models import Component, ComponentResult, Vulnerability
from .scanner import _severity

IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,499}$")


def available() -> bool:
    return shutil.which(os.environ.get("TRIVY_PATH", "trivy")) is not None


def _trivy_score(item: dict[str, Any]) -> float | None:
    scores = []
    for source in item.get("CVSS", {}).values():
        for key in ("V4Score", "V3Score", "V2Score"):
            if source.get(key) is not None:
                scores.append(float(source[key]))
                break
    return max(scores) if scores else None


def _to_vulnerability(item: dict[str, Any]) -> Vulnerability:
    vuln_id = item.get("VulnerabilityID", "UNKNOWN")
    score = _trivy_score(item)
    reported = str(item.get("Severity", "UNKNOWN")).upper()
    references = item.get("References", []) or []
    if item.get("PrimaryURL"):
        references = [item["PrimaryURL"], *references]
    return Vulnerability(
        id=vuln_id, aliases=[vuln_id], summary=item.get("Title") or item.get("Description") or "",
        severity=reported if reported in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else _severity(score),
        score=score, fixed_version=(str(item.get("FixedVersion", "")).split(",", 1)[0].strip() or None),
        published=item.get("PublishedDate"), modified=item.get("LastModifiedDate"),
        references=list(dict.fromkeys(references))[:5], source="Trivy",
    )


def parse_report(report: dict[str, Any], components: list[Component], container: Component | None = None) -> list[tuple[Component, Vulnerability]]:
    by_purl = {component.purl: component for component in components if component.purl}
    by_name_version = {(component.name.lower(), component.version or ""): component for component in components}
    findings = []
    for result in report.get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            component = container
            if component is None:
                purl = (item.get("PkgIdentifier") or {}).get("PURL")
                component = by_purl.get(purl)
                if component is None and purl and "@" in purl:
                    component = next((candidate for key, candidate in by_purl.items() if key and key.split("@", 1)[0] == purl.split("@", 1)[0] and candidate.version == item.get("InstalledVersion")), None)
                if component is None:
                    component = by_name_version.get((str(item.get("PkgName", "")).lower(), str(item.get("InstalledVersion", ""))))
            if component is not None:
                findings.append((component, _to_vulnerability(item)))
    return findings


async def _run_trivy(*args: str, timeout: int = 360) -> tuple[dict[str, Any] | None, str | None]:
    binary = os.environ.get("TRIVY_PATH", "trivy")
    try:
        process = await asyncio.create_subprocess_exec(
            binary, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        return None, f"Trivy timed out after {timeout} seconds"
    except OSError as exc:
        return None, f"Unable to start Trivy: {exc}"
    if process.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip().splitlines()
        return None, f"Trivy exited with code {process.returncode}: {(message[-1] if message else 'unknown error')[:300]}"
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, "Trivy returned invalid JSON"


async def scan(content: bytes, components: list[Component], scan_images: bool) -> tuple[list[tuple[Component, Vulnerability]], list[str], list[Component]]:
    if not available():
        return [], ["Trivy is not installed; OSV/NVD results are still available"], []
    findings: list[tuple[Component, Vulnerability]] = []
    warnings: list[str] = []
    scanned_containers: list[Component] = []
    path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False) as temp:
            temp.write(content)
            path = temp.name
        report, error = await _run_trivy("sbom", "--scanners", "vuln", "--format", "json", "--quiet", path)
        if report:
            findings.extend(parse_report(report, components))
        if error:
            warnings.append(error)
    finally:
        if path:
            Path(path).unlink(missing_ok=True)

    if scan_images:
        containers = [component for component in components if component.component_type == "container"]
        if len(containers) > 5:
            warnings.append("Only the first 5 container references were scanned")
        for component in containers[:5]:
            reference = component.name
            if not IMAGE_REF.fullmatch(reference):
                warnings.append(f"Skipped invalid container reference: {reference[:100]}")
                continue
            report, error = await _run_trivy("image", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", "5m", reference)
            if report:
                findings.extend(parse_report(report, components, container=component))
                scanned_containers.append(component)
            if error:
                warnings.append(f"{reference}: {error}")
    return findings, warnings, scanned_containers


def merge_findings(results: list[ComponentResult], findings: list[tuple[Component, Vulnerability]], scanned_containers: list[Component] | None = None) -> None:
    result_by_identity = {id(result.component): result for result in results}
    # Pydantic components from the parser are the same instances passed to Trivy mapping.
    for component, vuln in findings:
        result = result_by_identity.get(id(component))
        if result is None:
            result = next((item for item in results if item.component == component), None)
        if result is None:
            continue
        existing = next((item for item in result.vulnerabilities if item.id == vuln.id or set(item.aliases) & set(vuln.aliases)), None)
        if existing:
            existing.aliases = sorted(set(existing.aliases + vuln.aliases))
            existing.references = list(dict.fromkeys(existing.references + vuln.references))[:5]
            existing.fixed_version = existing.fixed_version or vuln.fixed_version
            if (vuln.score or 0) > (existing.score or 0):
                existing.score, existing.severity = vuln.score, vuln.severity
            if "Trivy" not in existing.source:
                existing.source += "+Trivy"
        else:
            result.vulnerabilities.append(vuln)
        result.status = "vulnerable"
    for component in scanned_containers or []:
        result = next((item for item in results if item.component == component), None)
        if result and result.status == "unknown":
            result.status = "clean"
            result.message = "Container image scanned by Trivy; no known vulnerabilities found"
