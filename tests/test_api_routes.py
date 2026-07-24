import json
from io import BytesIO
from zipfile import ZipFile

from fastapi import Response
from fastapi.testclient import TestClient

from app.main import app
from app.sbom_generator import GitAuthenticationRequired


def test_no_content_routes_use_empty_response_class():
    routes = {
        route.path: route
        for route in app.routes
        if getattr(route, "status_code", None) == 204
    }

    assert routes["/api/custom-advisories/{advisory_id}"].response_class is Response
    assert routes["/api/scans/{scan_id}"].response_class is Response


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
        return json.dumps({"bomFormat": "CycloneDX", "components": []}).encode()

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
