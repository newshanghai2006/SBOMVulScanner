from app.models import Component, ComponentResult
from app.trivy import configured_timeout, merge_findings, parse_report


def test_trivy_report_maps_purl_to_component():
    component = Component(name="demo", version="1.0", purl="pkg:pypi/demo@1.0")
    report = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-2026-0001", "PkgName": "demo", "InstalledVersion": "1.0",
        "PkgIdentifier": {"PURL": "pkg:pypi/demo@1.0"}, "Severity": "HIGH", "FixedVersion": "1.1",
        "CVSS": {"nvd": {"V3Score": 8.1}}, "Title": "Example",
    }]}]}
    findings = parse_report(report, [component])
    result = ComponentResult(component=component, status="clean")
    merge_findings([result], findings)
    assert result.status == "vulnerable"
    assert result.vulnerabilities[0].score == 8.1
    assert result.vulnerabilities[0].fixed_version == "1.1"


def test_trivy_timeout_is_configurable_and_bounded(monkeypatch):
    monkeypatch.setenv("TRIVY_TIMEOUT_SECONDS", "1800")
    assert configured_timeout() == 1800
    monkeypatch.setenv("TRIVY_TIMEOUT_SECONDS", "not-a-number")
    assert configured_timeout() == 900
    monkeypatch.setenv("TRIVY_TIMEOUT_SECONDS", "99999")
    assert configured_timeout() == 3600
