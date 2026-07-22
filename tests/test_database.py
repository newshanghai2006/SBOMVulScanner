from app import database
from app.models import Component, ComponentResult, ScanResult


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
