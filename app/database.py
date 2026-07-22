from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import ScanResult, ScanSummary

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
        connection.execute("CREATE INDEX IF NOT EXISTS scans_scanned_at_idx ON scans(scanned_at DESC)")


def save_scan(scan: ScanResult) -> None:
    with _connect() as connection:
        connection.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, document_type, document_name, document_hash, scanned_at,
                total_components, vulnerable_components, vulnerability_count,
                excluded_vulnerability_count, kev_count, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan.scan_id, scan.document_type, scan.document_name, scan.document_hash, scan.scanned_at,
            scan.total_components, scan.vulnerable_components, scan.vulnerability_count,
            scan.excluded_vulnerability_count, scan.kev_count, scan.model_dump_json(),
        ))


def get_scan(scan_id: str) -> ScanResult | None:
    with _connect() as connection:
        row = connection.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return ScanResult.model_validate_json(row["result_json"]) if row else None


def list_scans(limit: int = 20) -> list[ScanSummary]:
    with _connect() as connection:
        rows = connection.execute("""
            SELECT scan_id, document_type, document_name, document_hash, scanned_at,
                   total_components, vulnerable_components, vulnerability_count,
                   excluded_vulnerability_count, kev_count
            FROM scans ORDER BY scanned_at DESC LIMIT ?
        """, (min(max(limit, 1), 100),)).fetchall()
    return [ScanSummary.model_validate(dict(row)) for row in rows]


def delete_scan(scan_id: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    return cursor.rowcount > 0
