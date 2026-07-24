from app.models import Component, ComponentResult, EmergingThreat, ScanResult, Vulnerability
from app.report import markdown_report


def test_markdown_report_contains_risk_signals():
    scan = ScanResult(
        scan_id="scan-1", document_type="cyclonedx", document_name="bom.json", document_hash="abc",
        scanned_at="2026-01-01T00:00:00+08:00", total_components=1,
        vulnerable_components=1, vulnerability_count=1, kev_count=1, fixable_count=1,
        results=[ComponentResult(
            component=Component(name="demo", version="1.0", purl="pkg:pypi/demo@1.0"), status="vulnerable",
            vulnerabilities=[Vulnerability(
                id="CVE-2026-0001", aliases=["CVE-2026-0001", "GHSA-demo"], summary="Example",
                severity="HIGH", score=8.1, fixed_version="1.1", epss=0.8, kev=True, source="OSV",
            )],
        )],
        emerging_threats=[EmergingThreat(
            component="demo", component_purl="pkg:pypi/demo@1.0", installed_version="1.0",
            title="Unverified advisory", source_url="https://security.example/advisory",
            affected_version_claim="1.0", confidence="medium", reason="The cited source names version 1.0.",
        )],
    )
    report = markdown_report(scan)
    assert "CVE-2026-0001" in report
    assert "pkg:pypi/demo@1.0" in report
    assert "范围内风险组件 | 1" in report
    assert "80.00%" in report
    assert "GHSA-demo" in report
    assert "新兴威胁情报（未验证）" in report
    assert "https://security.example/advisory" in report
    assert "## 2. 风险概览与处置优先级" in report
    assert "## 3. 已匹配漏洞详情" in report
    assert "## 5. SBOM 完整性与未命中边界" in report
    assert "## 7. 推荐实施顺序" in report
    assert "P0" in report
