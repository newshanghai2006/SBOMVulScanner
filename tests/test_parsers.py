import json

import pytest

from app.parsers import DocumentError, parse_document


def encoded(data):
    return json.dumps(data).encode()


def test_parse_cyclonedx_purl():
    kind, components = parse_document(encoded({
        "bomFormat": "CycloneDX", "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0", "scope": "excluded"}
        ]
    }), "auto")
    assert kind == "cyclonedx"
    assert components[0].purl == "pkg:pypi/requests@2.31.0"
    assert components[0].scope == "excluded"


def test_parse_hbom_hardware():
    kind, components = parse_document(encoded({
        "bomFormat": "HBOM", "components": [
            {"name": "Router", "manufacturer": "Acme", "firmwareVersion": "1.2", "cpe": "cpe:2.3:h:acme:router:*:*:*:*:*:*:*:*"}
        ]
    }), "hbom")
    assert kind == "hbom"
    assert components[0].component_type == "hardware"
    assert components[0].version == "1.2"


def test_reject_mismatched_selected_type():
    with pytest.raises(DocumentError):
        parse_document(encoded({"bomFormat": "HBOM", "components": [{"name": "Router"}]}), "spdx")


def test_reject_unidentified_document():
    with pytest.raises(DocumentError):
        parse_document(encoded({"components": []}), "auto")
