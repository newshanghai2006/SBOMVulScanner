from app.main import apply_custom_advisories
from app.models import Component, ComponentResult, CustomAdvisory, Vulnerability


def advisory(**overrides):
    values = {
        "id": "LOCAL-TEST", "component_purl": "pkg:maven/com.example/demo", "exact_version": "1.0",
        "title": "Local advisory", "source_url": "https://security.example/advisory",
        "reason": "The exact version was manually confirmed", "created_at": "2026-01-01T00:00:00Z",
    }
    values.update(overrides)
    return CustomAdvisory(**values)


def test_custom_advisory_matches_only_exact_version():
    matching = ComponentResult(
        component=Component(name="demo", version="1.0", purl="pkg:maven/com.example/demo@1.0"), status="clean",
    )
    other = ComponentResult(
        component=Component(name="demo", version="1.1", purl="pkg:maven/com.example/demo@1.1"), status="clean",
    )
    assert apply_custom_advisories([matching, other], [advisory()]) == 1
    assert matching.status == "vulnerable"
    assert matching.vulnerabilities[0].source == "LocalIntel"
    assert other.status == "clean"
    assert other.vulnerabilities == []


def test_custom_advisory_merges_with_official_identifier():
    result = ComponentResult(
        component=Component(name="demo", version="1.0", purl="pkg:maven/com.example/demo@1.0"),
        status="vulnerable",
        vulnerabilities=[Vulnerability(id="CVE-2026-0001", aliases=["CVE-2026-0001"], source="OSV")],
    )
    apply_custom_advisories([result], [advisory(identifiers=["CVE-2026-0001"])])
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].source == "OSV+LocalIntel"
    assert "LOCAL-TEST" in result.vulnerabilities[0].aliases
