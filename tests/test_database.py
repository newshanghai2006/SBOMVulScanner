import sqlite3

from app import database
from app.models import Component, ComponentResult, CustomAdvisory, ScanResult


def test_legacy_database_is_quarantined_from_new_sessions(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE scans (
                scan_id TEXT PRIMARY KEY, document_type TEXT NOT NULL, document_name TEXT NOT NULL,
                document_hash TEXT, scanned_at TEXT NOT NULL, total_components INTEGER NOT NULL,
                vulnerable_components INTEGER NOT NULL, vulnerability_count INTEGER NOT NULL,
                excluded_vulnerability_count INTEGER NOT NULL DEFAULT 0, kev_count INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE custom_advisories (
                id TEXT PRIMARY KEY, component_purl TEXT NOT NULL, exact_version TEXT NOT NULL,
                title TEXT NOT NULL, source_url TEXT NOT NULL, identifiers_json TEXT NOT NULL DEFAULT '[]',
                severity TEXT NOT NULL DEFAULT 'UNKNOWN', reason TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(component_purl, exact_version, source_url)
            )
        """)
        connection.execute("""
            INSERT INTO scans VALUES (
                'old-scan', 'cyclonedx', 'old.json', NULL, '2026-01-01', 0, 0, 0, 0, 0, '{}'
            )
        """)
        connection.execute("""
            INSERT INTO custom_advisories VALUES (
                'OLD-LOCAL', 'pkg:pypi/demo', '1.0', 'Old', 'https://example.com', '[]',
                'UNKNOWN', 'Old shared record', '2026-01-01'
            )
        """)
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", db_path)

    database.initialize()

    with sqlite3.connect(db_path) as connection:
        scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        advisory_columns = {row[1] for row in connection.execute("PRAGMA table_info(custom_advisories)")}
        old_scan_owner = connection.execute("SELECT owner_id FROM scans WHERE scan_id = 'old-scan'").fetchone()[0]
        old_advisory_owner = connection.execute("SELECT owner_id FROM custom_advisories WHERE id = 'OLD-LOCAL'").fetchone()[0]
    assert "owner_id" in scan_columns
    assert "owner_id" in advisory_columns
    assert old_scan_owner == "legacy"
    assert old_advisory_owner == "legacy"
    assert database.list_scans("new-browser") == []
    assert database.list_custom_advisories("new-browser") == []


def test_scan_persistence(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.initialize()
    scan = ScanResult(
        scan_id="saved", document_type="cyclonedx", document_name="bom.json", document_hash="abc",
        scanned_at="2026-01-01T00:00:00Z", total_components=1, vulnerable_components=0,
        vulnerability_count=0, results=[ComponentResult(component=Component(name="demo"), status="unknown")],
    )
    database.save_scan(scan, "owner-a")
    assert database.get_scan("saved", "owner-a") == scan
    assert database.get_scan("saved", "owner-b") is None
    assert database.list_scans("owner-a")[0].document_hash == "abc"
    assert database.list_scans("owner-b") == []
    assert database.delete_scan("saved", "owner-b") is False
    assert database.delete_scan("saved", "owner-a") is True
    assert database.get_scan("saved", "owner-a") is None

    advisory = CustomAdvisory(
        id="LOCAL-TEST", component_purl="pkg:maven/com.example/demo", exact_version="1.0",
        title="Local advisory", source_url="https://security.example/advisory",
        reason="Manually confirmed exact version", created_at="2026-01-01T00:00:00Z",
    )
    database.save_custom_advisory(advisory, "owner-a")
    assert database.list_custom_advisories("owner-a") == [advisory]
    assert database.list_custom_advisories("owner-b") == []
    assert database.delete_custom_advisory("LOCAL-TEST", "owner-b") is False
    assert database.delete_custom_advisory("LOCAL-TEST", "owner-a") is True
    assert database.list_custom_advisories("owner-a") == []
