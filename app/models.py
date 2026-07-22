from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Component(BaseModel):
    name: str
    version: str | None = None
    vendor: str | None = None
    purl: str | None = None
    cpe: str | None = None
    ecosystem: str | None = None
    scope: Literal["required", "optional", "excluded", "unknown"] = "unknown"
    component_type: Literal["software", "hardware", "container"] = "software"


class Vulnerability(BaseModel):
    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: str = "UNKNOWN"
    score: float | None = None
    fixed_version: str | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    published: str | None = None
    modified: str | None = None
    references: list[str] = Field(default_factory=list)
    source: str


class EmergingThreat(BaseModel):
    component: str
    component_purl: str
    installed_version: str | None = None
    title: str = Field(min_length=1, max_length=500)
    source_url: str
    published_at: str | None = None
    identifiers: list[str] = Field(default_factory=list)
    affected_version_claim: str | None = None
    confidence: Literal["low", "medium", "high"] = "low"
    status: Literal["unverified"] = "unverified"
    reason: str = Field(min_length=1, max_length=1000)


class CustomAdvisoryCreate(BaseModel):
    component_purl: str = Field(min_length=5, max_length=1000)
    exact_version: str = Field(min_length=1, max_length=300)
    title: str = Field(min_length=1, max_length=500)
    source_url: str = Field(min_length=8, max_length=2000)
    identifiers: list[str] = Field(default_factory=list, max_length=20)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"
    reason: str = Field(min_length=1, max_length=1000)
    confirmed: bool


class CustomAdvisory(BaseModel):
    id: str
    component_purl: str
    exact_version: str
    title: str
    source_url: str
    identifiers: list[str] = Field(default_factory=list)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"
    reason: str
    created_at: str


class ComponentResult(BaseModel):
    component: Component
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    status: Literal["vulnerable", "clean", "unknown", "error"]
    message: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    document_type: str
    document_name: str
    document_hash: str | None = None
    scanned_at: str
    data_freshness: str = "Online OSV / NVD data with EPSS and CISA KEV enrichment"
    engines: list[str] = Field(default_factory=lambda: ["OSV", "NVD"])
    warnings: list[str] = Field(default_factory=list)
    emerging_threats: list[EmergingThreat] = Field(default_factory=list)
    total_components: int
    vulnerable_components: int
    vulnerability_count: int
    excluded_components: int = 0
    excluded_vulnerable_components: int = 0
    excluded_vulnerability_count: int = 0
    kev_count: int = 0
    fixable_count: int = 0
    results: list[ComponentResult]
    ai_summary: str | None = None


class ScanSummary(BaseModel):
    scan_id: str
    document_type: str
    document_name: str
    document_hash: str | None = None
    scanned_at: str
    total_components: int
    vulnerable_components: int
    vulnerability_count: int
    excluded_vulnerability_count: int = 0
    kev_count: int
