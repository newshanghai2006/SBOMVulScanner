from app import database
from app.models import Component, ComponentResult, CustomAdvisory, ScanResult


def test_scan_persistence(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.initialize()
    scan = ScanResult(
        scan_id="saved", document_type="cyclonedx", document_name="bom.json", document_hash="abc",
        scanned_at="2026-01-01T00:00:00Z", total_components=1, vulnerable_components=0,
        vulnerability_count=0, results=[ComponentResult(component=Component(name="demo"), status="unknown")],
    )
    database.save_scan(scan)
    assert database.get_scan("saved") == scan
    assert database.list_scans()[0].document_hash == "abc"
    assert database.delete_scan("saved") is True
    assert database.get_scan("saved") is None

    advisory = CustomAdvisory(
        id="LOCAL-TEST", component_purl="pkg:maven/com.example/demo", exact_version="1.0",
        title="Local advisory", source_url="https://security.example/advisory",
        reason="Manually confirmed exact version", created_at="2026-01-01T00:00:00Z",
    )
    database.save_custom_advisory(advisory)
    assert database.list_custom_advisories() == [advisory]
    assert database.delete_custom_advisory("LOCAL-TEST") is True
    assert database.list_custom_advisories() == []
