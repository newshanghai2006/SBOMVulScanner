import json
import hashlib
from io import BytesIO
from zipfile import ZipFile

from fastapi import Response
from fastapi.testclient import TestClient

from app.main import app
from app import database
from app.models import Component, ComponentResult, ScanResult
from app.sbom_generator import GitAuthenticationRequired


def test_no_content_routes_use_empty_response_class():
    routes = {
        route.path: route
        for route in app.routes
        if getattr(route, "status_code", None) == 204
    }

    assert routes["/api/custom-advisories/{advisory_id}"].response_class is Response
    assert routes["/api/scans/{scan_id}"].response_class is Response


def test_frontend_assets_disable_browser_cache():
    client = TestClient(app)
    page = client.get("/")
    script = client.get("/app.js")
    favicon = client.get("/favicon.svg?v=1")

    assert page.headers["cache-control"] == "no-store"
    assert script.headers["cache-control"] == "no-store"
    assert "/app.js?v=2.5.0" in page.text
    assert '/favicon.svg?v=1' in page.text
    assert favicon.headers["content-type"].startswith("image/svg+xml")
    assert '#167454' in favicon.text
    assert '>SS<' in favicon.text


def test_scan_history_is_isolated_by_browser_session(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "sessions.db")
    database.initialize()
    client_a = TestClient(app)
    client_b = TestClient(app)

    page = client_a.get("/")
    cookie = client_a.cookies.get("sbom_scan_session")
    owner_a = hashlib.sha256(cookie.encode("ascii")).hexdigest()
    scan = ScanResult(
        scan_id="private-scan", document_type="cyclonedx", document_name="private.json",
        scanned_at="2026-01-01T00:00:00Z", total_components=1, vulnerable_components=0,
        vulnerability_count=0,
        results=[ComponentResult(component=Component(name="private-component"), status="unknown")],
    )
    database.save_scan(scan, owner_a)

    assert "HttpOnly" in page.headers["set-cookie"]
    assert "SameSite=strict" in page.headers["set-cookie"]
    assert client_a.get("/api/scans").json()[0]["scan_id"] == "private-scan"
    assert client_b.get("/api/scans").json() == []
    assert client_b.get("/api/scans/private-scan").status_code == 404
    assert client_b.get("/api/report/private-scan").status_code == 404
    assert client_b.delete("/api/scans/private-scan").status_code == 404
    assert client_a.get("/api/scans/private-scan").status_code == 200


def test_generate_sbom_requires_exactly_one_source():
    response = TestClient(app).post("/api/generate-sbom", data={"output_format": "cyclonedx"})

    assert response.status_code == 400
    assert "exactly one source" in response.json()["detail"]


def test_generate_sbom_from_zip_returns_download(monkeypatch):
    archive = BytesIO()
    with ZipFile(archive, "w") as output:
        output.writestr("project/requirements.txt", "fastapi==0.116.1")

    async def fake_generate(_source, output_format):
        assert output_format == "cyclonedx"
        return json.dumps({"bomFormat": "CycloneDX", "components": []}).encode(), 0

    monkeypatch.setattr("app.main.generate_sbom", fake_generate)
    response = TestClient(app).post(
        "/api/generate-sbom",
        data={"output_format": "cyclonedx"},
        files={"source_zip": ("device-center.zip", archive.getvalue(), "application/zip")},
    )

    assert response.status_code == 200
    assert response.json()["bomFormat"] == "CycloneDX"
    assert response.headers["content-disposition"] == 'attachment; filename="device-center.cdx.json"'
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-sbom-format"] == "cyclonedx"
    assert response.headers["x-sbom-component-count"] == "0"


def test_git_authentication_failure_returns_401(monkeypatch):
    async def authentication_required(*_args, **_kwargs):
        raise GitAuthenticationRequired("仓库需要认证")

    monkeypatch.setattr("app.main.clone_repository", authentication_required)
    response = TestClient(app).post("/api/generate-sbom", data={
        "output_format": "cyclonedx",
        "git_command": "git clone https://git.example.com/group/project.git",
    })

    assert response.status_code == 401
    assert response.json()["detail"] == "仓库需要认证"
