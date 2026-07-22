from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .models import CustomAdvisory, CustomAdvisoryCreate, ScanResult, ScanSummary, Vulnerability
from .parsers import DocumentError, parse_document
from .report import markdown_report
from .scanner import SEVERITY_ORDER, enrich_risk, scan_components
from . import trivy
from .threat_intel import search_emerging_threats

BASE_DIR = Path(__file__).resolve().parent.parent
MAX_FILE_SIZE = 5 * 1024 * 1024

database.initialize()
app = FastAPI(title="SBOM Scan", version="2.3.0")


def _purl_base(purl: str) -> str:
    return purl.rsplit("@", 1)[0].lower()


def apply_custom_advisories(results, advisories: list[CustomAdvisory]) -> int:
    matched = 0
    for result in results:
        component = result.component
        if not component.purl or not component.version:
            continue
        for advisory in advisories:
            if _purl_base(component.purl) != advisory.component_purl or component.version != advisory.exact_version:
                continue
            matched += 1
            aliases = sorted(set([advisory.id, *advisory.identifiers]))
            existing = next((vuln for vuln in result.vulnerabilities if set(vuln.aliases) & set(advisory.identifiers)), None)
            if existing:
                existing.aliases = sorted(set(existing.aliases + aliases))
                existing.references = list(dict.fromkeys(existing.references + [advisory.source_url]))[:5]
                if "LocalIntel" not in existing.source:
                    existing.source += "+LocalIntel"
            else:
                result.vulnerabilities.append(Vulnerability(
                    id=advisory.id, aliases=aliases, summary=f"{advisory.title} - {advisory.reason}",
                    severity=advisory.severity, published=advisory.created_at,
                    references=[advisory.source_url], source="LocalIntel",
                ))
            result.status = "vulnerable"
    return matched


async def create_ai_summary(scan: ScanResult, base_url: str, api_key: str, model: str) -> str:
    risky = [{
        "component": result.component.name,
        "version": result.component.version,
        "vulnerabilities": [{"id": vuln.id, "severity": vuln.severity, "kev": vuln.kev} for vuln in result.vulnerabilities],
    } for result in scan.results if result.component.scope != "excluded" and result.vulnerabilities]
    if not risky:
        return "No known vulnerabilities were matched; an additional risk summary is not necessary."
    endpoint = base_url.rstrip("/")
    if endpoint.endswith("/responses"):
        endpoint = endpoint[:-len("/responses")]
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"
    prompt = (
        "Based only on the confirmed matches below, write a concise Chinese remediation priority summary. "
        "Do not invent CVEs or claim exploitability without evidence.\n" + json.dumps(risky, ensure_ascii=False)
    )
    async with httpx.AsyncClient(timeout=45) as client:
        response = await client.post(endpoint, headers={"Authorization": f"Bearer {api_key}"}, json={
            "model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1,
        })
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get("/api/scans", response_model=list[ScanSummary])
async def scan_history(limit: int = 20) -> list[ScanSummary]:
    return database.list_scans(limit)


@app.get("/api/custom-advisories", response_model=list[CustomAdvisory])
async def custom_advisories() -> list[CustomAdvisory]:
    return database.list_custom_advisories()


@app.post("/api/custom-advisories", response_model=CustomAdvisory, status_code=201)
async def create_custom_advisory(payload: CustomAdvisoryCreate) -> CustomAdvisory:
    if not payload.confirmed:
        raise HTTPException(400, "Explicit confirmation is required")
    if not payload.component_purl.startswith("pkg:"):
        raise HTTPException(400, "A valid package URL is required")
    if not payload.source_url.startswith(("https://", "http://")):
        raise HTTPException(400, "A cited HTTP(S) source URL is required")
    advisory = CustomAdvisory(
        id="LOCAL-" + uuid.uuid4().hex[:12].upper(),
        component_purl=_purl_base(payload.component_purl), exact_version=payload.exact_version,
        title=payload.title, source_url=payload.source_url,
        identifiers=sorted(set(payload.identifiers)), severity=payload.severity,
        reason=payload.reason,
        created_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    )
    try:
        database.save_custom_advisory(advisory)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "This source is already confirmed for the component version") from exc
    return advisory


@app.delete("/api/custom-advisories/{advisory_id}", status_code=204)
async def remove_custom_advisory(advisory_id: str) -> None:
    if not database.delete_custom_advisory(advisory_id):
        raise HTTPException(404, "Custom advisory not found")


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def saved_scan(scan_id: str) -> ScanResult:
    result = database.get_scan(scan_id)
    if not result:
        raise HTTPException(404, "Scan result not found")
    return result


@app.delete("/api/scans/{scan_id}", status_code=204)
async def remove_scan(scan_id: str) -> None:
    if not database.delete_scan(scan_id):
        raise HTTPException(404, "Scan result not found")


@app.post("/api/scan", response_model=ScanResult)
async def scan(
    file: UploadFile = File(...), document_type: str = Form("auto"),
    nvd_api_key: str | None = Form(None), llm_base_url: str | None = Form(None),
    llm_api_key: str | None = Form(None), llm_model: str = Form("gpt-4.1-mini"),
    scan_engine: str = Form("auto"), scan_container_images: bool = Form(False),
    ai_summary_enabled: bool = Form(False), ai_threat_search: bool = Form(False),
    threat_max_components: int = Form(10), threat_days: int = Form(30),
) -> ScanResult:
    content = await file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "File size must not exceed 5 MB")
    try:
        detected_type, components = parse_document(content, document_type)
    except DocumentError as exc:
        raise HTTPException(400, str(exc)) from exc

    if scan_engine not in {"auto", "osv", "hybrid"}:
        raise HTTPException(400, "scan_engine must be auto, osv, or hybrid")
    results = await scan_components(components, nvd_api_key)
    engines = ["OSV", "NVD"]
    warnings: list[str] = []
    requested_trivy = scan_engine == "hybrid" or (scan_engine == "auto" and trivy.available())
    use_trivy = requested_trivy and trivy.available()
    if use_trivy:
        findings, trivy_warnings, scanned_containers = await trivy.scan(content, components, scan_container_images)
        trivy.merge_findings(results, findings, scanned_containers)
        warnings.extend(trivy_warnings)
        engines.append("Trivy")
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "SBOM-Scan/2.0"}) as client:
            await enrich_risk(client, results)
        for item in results:
            item.vulnerabilities.sort(key=lambda vuln: (not vuln.kev, SEVERITY_ORDER.get(vuln.severity, 4), -(vuln.epss or 0), vuln.id))
    elif requested_trivy:
        warnings.append("Trivy is not installed; the scan completed with OSV/NVD only")
    local_matches = apply_custom_advisories(results, database.list_custom_advisories())
    if local_matches:
        engines.append("LocalIntel")
        for item in results:
            item.vulnerabilities.sort(key=lambda vuln: (not vuln.kev, SEVERITY_ORDER.get(vuln.severity, 4), -(vuln.epss or 0), vuln.id))
    active_results = [result for result in results if result.component.scope != "excluded"]
    excluded_results = [result for result in results if result.component.scope == "excluded"]
    vulnerabilities = [vuln for result in active_results for vuln in result.vulnerabilities]
    excluded_vulnerabilities = [vuln for result in excluded_results for vuln in result.vulnerabilities]
    scan_result = ScanResult(
        scan_id=str(uuid.uuid4()), document_type=detected_type,
        document_name=file.filename or "document.json", document_hash=hashlib.sha256(content).hexdigest(),
        scanned_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        total_components=len(results), vulnerable_components=sum(result.status == "vulnerable" for result in active_results),
        vulnerability_count=len(vulnerabilities), kev_count=sum(vuln.kev for vuln in vulnerabilities),
        fixable_count=sum(vuln.fixed_version is not None for vuln in vulnerabilities), results=results,
        excluded_components=len(excluded_results),
        excluded_vulnerable_components=sum(result.status == "vulnerable" for result in excluded_results),
        excluded_vulnerability_count=len(excluded_vulnerabilities),
        engines=engines, warnings=warnings,
    )
    if ai_threat_search:
        if llm_base_url and llm_api_key:
            emerging, threat_warnings = await search_emerging_threats(
                components, llm_base_url, llm_api_key, llm_model,
                max_components=threat_max_components, days=threat_days,
            )
            scan_result.emerging_threats = emerging
            scan_result.warnings.extend(threat_warnings)
        else:
            scan_result.warnings.append("AI threat search requires both LLM Base URL and API key")
    if ai_summary_enabled:
        if not (llm_base_url and llm_api_key):
            scan_result.warnings.append("AI summary requires both LLM Base URL and API key")
        else:
            try:
                scan_result.ai_summary = await create_ai_summary(scan_result, llm_base_url, llm_api_key, llm_model)
            except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
                scan_result.ai_summary = f"AI summary failed ({type(exc).__name__}); vulnerability results are unaffected."
    database.save_scan(scan_result)
    return scan_result


@app.get("/api/report/{scan_id}", response_class=PlainTextResponse)
async def report(scan_id: str) -> PlainTextResponse:
    result = database.get_scan(scan_id)
    if not result:
        raise HTTPException(404, "Scan result not found")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(result.document_name).stem)
    return PlainTextResponse(markdown_report(result), media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{safe_name}-vulnerability-report.md"'
    })


app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
