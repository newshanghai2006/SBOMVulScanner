import json

from app.models import Component
from app.threat_intel import parse_response, responses_endpoint, select_components


def response_with(threats, cited_url="https://security.example/advisory"):
    return {
        "output": [{
            "type": "message",
            "content": [{
                "type": "output_text",
                "text": json.dumps({"threats": threats}),
                "annotations": [{"type": "url_citation", "url": cited_url, "title": "Advisory"}],
            }],
        }],
    }


def test_parse_response_requires_citation_and_exact_component():
    component = Component(name="fastjson", version="1.2.83", purl="pkg:maven/com.alibaba/fastjson@1.2.83")
    item = {
        "component_purl": component.purl, "title": "Security advisory",
        "source_url": "https://security.example/advisory", "published_at": "2026-07-20",
        "identifiers": [], "affected_version_claim": "1.2.83", "confidence": "medium",
        "reason": "The source explicitly names version 1.2.83.",
    }
    threats, warnings = parse_response(response_with([item]), {component.purl: component})
    assert not warnings
    assert threats[0].status == "unverified"
    assert threats[0].component == "fastjson"


def test_parse_response_discards_uncited_model_url():
    component = Component(name="demo", version="1", purl="pkg:npm/demo@1")
    item = {
        "component_purl": component.purl, "title": "Invented", "source_url": "https://invented.example/post",
        "confidence": "high", "reason": "Unsupported claim",
    }
    threats, warnings = parse_response(response_with([item]), {component.purl: component})
    assert threats == []
    assert "Discarded 1" in warnings[0]


def test_component_selection_excludes_excluded_scope_and_prioritizes_sensitive_packages():
    components = [
        Component(name="ordinary", version="1", purl="pkg:npm/ordinary@1", scope="required"),
        Component(name="fastjson", version="1", purl="pkg:maven/x/fastjson@1", scope="required"),
        Component(name="openssl", version="1", purl="pkg:generic/openssl@1", scope="excluded"),
    ]
    selected = select_components(components, 1)
    assert [item.name for item in selected] == ["fastjson"]


def test_responses_endpoint_accepts_api_root_or_existing_endpoint():
    assert responses_endpoint("https://api.openai.com/v1") == "https://api.openai.com/v1/responses"
    assert responses_endpoint("https://api.openai.com/v1/chat/completions") == "https://api.openai.com/v1/responses"
