from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import CustomAdvisory, ScanResult, ScanSummary

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "sbom-scan.db"


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def initialize() -> None:
    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL DEFAULT 'legacy',
                document_type TEXT NOT NULL,
                document_name TEXT NOT NULL,
                document_hash TEXT,
                scanned_at TEXT NOT NULL,
                total_components INTEGER NOT NULL,
                vulnerable_components INTEGER NOT NULL,
                vulnerability_count INTEGER NOT NULL,
                excluded_vulnerability_count INTEGER NOT NULL DEFAULT 0,
                kev_count INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        if "excluded_vulnerability_count" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN excluded_vulnerability_count INTEGER NOT NULL DEFAULT 0")
        if "owner_id" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'legacy'")
        connection.execute("CREATE INDEX IF NOT EXISTS scans_owner_time_idx ON scans(owner_id, scanned_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS custom_advisories (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                component_purl TEXT NOT NULL,
                exact_version TEXT NOT NULL,
                title TEXT NOT NULL,
                source_url TEXT NOT NULL,
                identifiers_json TEXT NOT NULL DEFAULT '[]',
                severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(owner_id, component_purl, exact_version, source_url)
            )
        """)
        advisory_columns = {row["name"] for row in connection.execute("PRAGMA table_info(custom_advisories)")}
        if "owner_id" not in advisory_columns:
            connection.execute("DROP INDEX IF EXISTS custom_advisories_component_idx")
            connection.execute("ALTER TABLE custom_advisories RENAME TO custom_advisories_legacy")
            connection.execute("""
                CREATE TABLE custom_advisories (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    component_purl TEXT NOT NULL,
                    exact_version TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    identifiers_json TEXT NOT NULL DEFAULT '[]',
                    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(owner_id, component_purl, exact_version, source_url)
                )
            """)
            connection.execute("""
                INSERT INTO custom_advisories (
                    id, owner_id, component_purl, exact_version, title, source_url,
                    identifiers_json, severity, reason, created_at
                )
                SELECT id, 'legacy', component_purl, exact_version, title, source_url,
                       identifiers_json, severity, reason, created_at
                FROM custom_advisories_legacy
            """)
            connection.execute("DROP TABLE custom_advisories_legacy")
        connection.execute("CREATE INDEX IF NOT EXISTS custom_advisories_owner_component_idx ON custom_advisories(owner_id, component_purl, exact_version)")


def save_scan(scan: ScanResult, owner_id: str) -> None:
    with _connect() as connection:
        connection.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, owner_id, document_type, document_name, document_hash, scanned_at,
                total_components, vulnerable_components, vulnerability_count,
                excluded_vulnerability_count, kev_count, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan.scan_id, owner_id, scan.document_type, scan.document_name, scan.document_hash, scan.scanned_at,
            scan.total_components, scan.vulnerable_components, scan.vulnerability_count,
            scan.excluded_vulnerability_count, scan.kev_count, scan.model_dump_json(),
        ))


def get_scan(scan_id: str, owner_id: str) -> ScanResult | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM scans WHERE scan_id = ? AND owner_id = ?", (scan_id, owner_id),
        ).fetchone()
    return ScanResult.model_validate_json(row["result_json"]) if row else None


def list_scans(owner_id: str, limit: int = 20) -> list[ScanSummary]:
    with _connect() as connection:
        rows = connection.execute("""
            SELECT scan_id, document_type, document_name, document_hash, scanned_at,
                   total_components, vulnerable_components, vulnerability_count,
                   excluded_vulnerability_count, kev_count
            FROM scans WHERE owner_id = ? ORDER BY scanned_at DESC LIMIT ?
        """, (owner_id, min(max(limit, 1), 100))).fetchall()
    return [ScanSummary.model_validate(dict(row)) for row in rows]


def delete_scan(scan_id: str, owner_id: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute("DELETE FROM scans WHERE scan_id = ? AND owner_id = ?", (scan_id, owner_id))
    return cursor.rowcount > 0


def save_custom_advisory(advisory: CustomAdvisory, owner_id: str) -> None:
    with _connect() as connection:
        connection.execute("""
            INSERT INTO custom_advisories (
                id, owner_id, component_purl, exact_version, title, source_url,
                identifiers_json, severity, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            advisory.id, owner_id, advisory.component_purl, advisory.exact_version, advisory.title,
            advisory.source_url, json.dumps(advisory.identifiers, ensure_ascii=False),
            advisory.severity, advisory.reason, advisory.created_at,
        ))


def list_custom_advisories(owner_id: str) -> list[CustomAdvisory]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM custom_advisories WHERE owner_id = ? ORDER BY created_at DESC", (owner_id,),
        ).fetchall()
    return [CustomAdvisory(
        id=row["id"], component_purl=row["component_purl"], exact_version=row["exact_version"],
        title=row["title"], source_url=row["source_url"], identifiers=json.loads(row["identifiers_json"]),
        severity=row["severity"], reason=row["reason"], created_at=row["created_at"],
    ) for row in rows]


def delete_custom_advisory(advisory_id: str, owner_id: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute(
            "DELETE FROM custom_advisories WHERE id = ? AND owner_id = ?", (advisory_id, owner_id),
        )
    return cursor.rowcount > 0
