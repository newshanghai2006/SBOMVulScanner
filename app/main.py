from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .models import CustomAdvisory, CustomAdvisoryCreate, ScanResult, ScanSummary, Vulnerability
from .parsers import DocumentError, parse_document
from .report import markdown_report
from .scanner import SEVERITY_ORDER, enrich_risk, scan_components
from .sbom_generator import (
    MAX_ARCHIVE_SIZE,
    GenerationError,
    GitAuthenticationRequired,
    clone_repository,
    extract_zip,
    generate_sbom,
    parse_git_clone,
    validate_source_tree,
)
from . import trivy
from .threat_intel import search_emerging_threats

BASE_DIR = Path(__file__).resolve().parent.parent
MAX_FILE_SIZE = 100 * 1024 * 1024

database.initialize()
app = FastAPI(title="SBOM Scan", version="2.7.0")
SESSION_COOKIE = "sbom_scan_session"
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


@app.middleware("http")
async def disable_frontend_cache(request: Request, call_next):
    session_token = request.cookies.get(SESSION_COOKIE, "")
    new_session = not SESSION_PATTERN.fullmatch(session_token)
    if new_session:
        session_token = secrets.token_urlsafe(32)
    request.state.owner_id = hashlib.sha256(session_token.encode("ascii")).hexdigest()
    response = await call_next(request)
    if request.url.path in {"/", "/index.html", "/app.js", "/styles.css"}:
        response.headers["Cache-Control"] = "no-store"
    if new_session:
        response.set_cookie(
            SESSION_COOKIE, session_token, max_age=365 * 24 * 60 * 60,
            httponly=True, secure=request.url.scheme == "https", samesite="strict", path="/",
        )
    return response


def _purl_base(purl: str) -> str:
    return purl.rsplit("@", 1)[0].lower()


async def _save_upload(upload: UploadFile, target: Path, limit: int) -> int:
    size = 0
    with target.open("wb") as output:
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise HTTPException(413, "Source ZIP must not exceed 1000 MB")
            output.write(chunk)
    return size


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
async def scan_history(request: Request, limit: int = 20) -> list[ScanSummary]:
    return database.list_scans(request.state.owner_id, limit)


@app.get("/api/custom-advisories", response_model=list[CustomAdvisory])
async def custom_advisories(request: Request) -> list[CustomAdvisory]:
    return database.list_custom_advisories(request.state.owner_id)


@app.post("/api/custom-advisories", response_model=CustomAdvisory, status_code=201)
async def create_custom_advisory(payload: CustomAdvisoryCreate, request: Request) -> CustomAdvisory:
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
        database.save_custom_advisory(advisory, request.state.owner_id)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "This source is already confirmed for the component version") from exc
    return advisory


@app.delete("/api/custom-advisories/{advisory_id}", status_code=204, response_class=Response)
async def remove_custom_advisory(advisory_id: str, request: Request) -> Response:
    if not database.delete_custom_advisory(advisory_id, request.state.owner_id):
        raise HTTPException(404, "Custom advisory not found")
    return Response(status_code=204)


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def saved_scan(scan_id: str, request: Request) -> ScanResult:
    result = database.get_scan(scan_id, request.state.owner_id)
    if not result:
        raise HTTPException(404, "Scan result not found")
    return result


@app.delete("/api/scans/{scan_id}", status_code=204, response_class=Response)
async def remove_scan(scan_id: str, request: Request) -> Response:
    if not database.delete_scan(scan_id, request.state.owner_id):
        raise HTTPException(404, "Scan result not found")
    return Response(status_code=204)


@app.post("/api/generate-sbom")
async def create_sbom(
    source_zip: UploadFile | None = File(None),
    git_command: str | None = Form(None),
    git_username: str | None = Form(None),
    git_password: str | None = Form(None),
    output_format: str = Form("cyclonedx"),
) -> Response:
    has_zip = bool(source_zip and source_zip.filename)
    command = (git_command or "").strip()
    if has_zip == bool(command):
        raise HTTPException(400, "Provide exactly one source: a ZIP file or a git clone command")
    if output_format not in {"cyclonedx", "spdx"}:
        raise HTTPException(400, "Output format must be cyclonedx or spdx")

    try:
        with tempfile.TemporaryDirectory(prefix="sbom-source-") as temp_name:
            workspace = Path(temp_name)
            source_dir = workspace / "source"
            if has_zip and source_zip:
                archive_path = workspace / "source.zip"
                await _save_upload(source_zip, archive_path, MAX_ARCHIVE_SIZE)
                await asyncio.to_thread(extract_zip, archive_path, source_dir)
                await asyncio.to_thread(validate_source_tree, source_dir)
                source_name = Path(source_zip.filename or "source").stem
            else:
                git_source = parse_git_clone(command)
                username = (git_username or "").strip() or None
                password = git_password or None
                if username and len(username) > 200:
                    raise HTTPException(400, "Git username is too long")
                if password and len(password) > 2000:
                    raise HTTPException(400, "Git password or token is too long")
                await clone_repository(git_source, source_dir, username, password)
                source_name = Path(git_source.url.rstrip("/").rsplit("/", 1)[-1]).stem
            document, component_count = await generate_sbom(source_dir, output_format)
    except GitAuthenticationRequired as exc:
        raise HTTPException(401, str(exc)) from exc
    except GenerationError as exc:
        raise HTTPException(400, str(exc)) from exc

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", source_name).strip("._") or "source"
    suffix = "cdx.json" if output_format == "cyclonedx" else "spdx.json"
    return Response(document, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{safe_name}.{suffix}"',
        "Cache-Control": "no-store",
        "X-SBOM-Format": output_format,
        "X-SBOM-Component-Count": str(component_count),
    })


@app.post("/api/scan", response_model=ScanResult)
async def scan(
    request: Request, file: UploadFile = File(...), document_type: str = Form("auto"),
    nvd_api_key: str | None = Form(None), llm_base_url: str | None = Form(None),
    llm_api_key: str | None = Form(None), llm_model: str = Form("gpt-4.1-mini"),
    scan_engine: str = Form("auto"), scan_container_images: bool = Form(False),
    ai_summary_enabled: bool = Form(False), ai_threat_search: bool = Form(False),
    threat_max_components: int = Form(10), threat_days: int = Form(30),
) -> ScanResult:
    content = await file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "File size must not exceed 100 MB")
    try:
        detected_type, components = parse_document(content, document_type)
    except DocumentError as exc:
        raise HTTPException(400, str(exc)) from exc

    if scan_engine not in {"auto", "osv", "hybrid"}:
        raise HTTPException(400, "scan_engine must be auto, osv, or hybrid")
    results = await scan_components(components, nvd_api_key)
    engines = ["OSV", "NVD"]
    warnings: list[str] = []
    if any(item.status == "error" and (item.message or "").startswith("OSV query failed") for item in results):
        warnings.append("OSV 请求在重试后仍不可用；相关组件标记为查询失败，未按干净处理。请检查服务器到 api.osv.dev 的网络、代理或稍后重试。")
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
    local_matches = apply_custom_advisories(results, database.list_custom_advisories(request.state.owner_id))
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
    database.save_scan(scan_result, request.state.owner_id)
    return scan_result


@app.get("/api/report/{scan_id}", response_class=PlainTextResponse)
async def report(scan_id: str, request: Request) -> PlainTextResponse:
    result = database.get_scan(scan_id, request.state.owner_id)
    if not result:
        raise HTTPException(404, "Scan result not found")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(result.document_name).stem)
    return PlainTextResponse(markdown_report(result), media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{safe_name}-vulnerability-report.md"'
    })


app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
