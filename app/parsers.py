from __future__ import annotations

import json
from typing import Any

from .models import Component


class DocumentError(ValueError):
    pass


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _scope(value: Any) -> str:
    scope = str(value or "unknown").lower()
    return scope if scope in {"required", "optional", "excluded"} else "unknown"


def parse_document(content: bytes, requested_type: str) -> tuple[str, list[Component]]:
    try:
        data = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DocumentError(f"文件不是有效的 UTF-8 JSON：{exc}") from exc

    if not isinstance(data, dict):
        raise DocumentError("文档根节点必须是 JSON 对象")

    detected = detect_type(data)
    if requested_type != "auto" and requested_type != detected:
        raise DocumentError(f"所选类型为 {requested_type}，但文件识别为 {detected}")

    parsers = {
        "cyclonedx": parse_cyclonedx,
        "spdx": parse_spdx,
        "hbom": parse_hbom,
    }
    components = parsers[detected](data)
    if not components:
        raise DocumentError("文档中没有可扫描的组件")
    if len(components) > 500:
        raise DocumentError("单次最多扫描 500 个组件")
    return detected, components


def detect_type(data: dict[str, Any]) -> str:
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in data or "packages" in data and "SPDXID" in data:
        return "spdx"
    if data.get("bomFormat") == "HBOM" or data.get("documentType") == "HBOM":
        return "hbom"
    raise DocumentError("无法识别文档格式；支持 CycloneDX JSON、SPDX JSON 和本项目 HBOM JSON")


def parse_cyclonedx(data: dict[str, Any]) -> list[Component]:
    result = []
    for item in data.get("components", []):
        if not isinstance(item, dict):
            continue
        result.append(Component(
            name=_clean(item.get("name")) or "unknown",
            version=_clean(item.get("version")),
            vendor=_clean(item.get("supplier", {}).get("name") if isinstance(item.get("supplier"), dict) else item.get("publisher")),
            purl=_clean(item.get("purl")),
            cpe=_clean(item.get("cpe")),
            scope=_scope(item.get("scope")),
            component_type="hardware" if item.get("type") == "device" else ("container" if item.get("type") == "container" else "software"),
        ))
    return result


def parse_spdx(data: dict[str, Any]) -> list[Component]:
    result = []
    for item in data.get("packages", []):
        if not isinstance(item, dict):
            continue
        purl = cpe = None
        for ref in item.get("externalRefs", []):
            ref_type = str(ref.get("referenceType", "")).lower()
            locator = _clean(ref.get("referenceLocator"))
            if "purl" in ref_type:
                purl = locator
            elif "cpe" in ref_type:
                cpe = locator
        result.append(Component(
            name=_clean(item.get("name")) or "unknown",
            version=_clean(item.get("versionInfo")),
            vendor=_clean(item.get("supplier") or item.get("originator")),
            purl=purl,
            cpe=cpe,
            scope="unknown",
        ))
    return result


def parse_hbom(data: dict[str, Any]) -> list[Component]:
    result = []
    for item in data.get("components", []):
        if not isinstance(item, dict):
            continue
        if not item.get("name"):
            raise DocumentError("HBOM 每个组件必须包含 name")
        result.append(Component(
            name=_clean(item.get("name")) or "unknown",
            version=_clean(item.get("firmwareVersion") or item.get("version")),
            vendor=_clean(item.get("manufacturer") or item.get("vendor")),
            cpe=_clean(item.get("cpe")),
            purl=_clean(item.get("purl")),
            scope=_scope(item.get("scope")),
            component_type="hardware",
        ))
    return result
