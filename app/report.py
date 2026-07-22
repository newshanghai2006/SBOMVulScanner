from __future__ import annotations

from .models import ScanResult


def markdown_report(scan: ScanResult) -> str:
    lines = [
        f"# SBOM/HBOM Vulnerability Report: {scan.document_name}", "",
        f"- Scanned at: {scan.scanned_at}",
        f"- Document type: {scan.document_type}",
        f"- SHA-256: `{scan.document_hash or 'not recorded'}`",
        f"- Components: {scan.total_components}",
        f"- In-scope vulnerable components: {scan.vulnerable_components}",
        f"- In-scope vulnerability records: {scan.vulnerability_count}",
        f"- Excluded components: {scan.excluded_components}",
        f"- Excluded-scope findings: {scan.excluded_vulnerability_count}",
        f"- Known exploited (CISA KEV): {scan.kev_count}",
        f"- Findings with a known fix: {scan.fixable_count}",
        f"- Engines: {', '.join(scan.engines)}",
        f"- Data: {scan.data_freshness}", "",
        "> Database matches are potential exposure. Validate reachability, deployment context, vendor advisories, and VEX before making a final risk decision.", "",
    ]
    if scan.warnings:
        lines.extend(["## Scan Warnings", "", *[f"- {warning}" for warning in scan.warnings], ""])
    if scan.ai_summary:
        lines.extend(["## AI Risk Summary", "", scan.ai_summary, ""])
    if scan.emerging_threats:
        lines.extend([
            "## Emerging Threat Intelligence (Unverified)", "",
            "> These web-search findings are not part of the confirmed vulnerability totals. Review every cited source before taking action.", "",
            "| Confidence | Component | Installed | Version claim | Identifiers | Source | Reason |",
            "|---|---|---|---|---|---|---|",
        ])
        for threat in scan.emerging_threats:
            reason = threat.reason.replace("|", "\\|").replace("\n", " ")
            title = threat.title.replace("|", "\\|")
            identifiers = ", ".join(threat.identifiers) or "No standard identifier"
            lines.append(
                f"| {threat.confidence.upper()} | `{threat.component_purl}` | {threat.installed_version or '-'} | "
                f"{threat.affected_version_claim or '-'} | {identifiers} | [{title}]({threat.source_url}) | {reason} |"
            )
        lines.append("")
    lines.extend(["## In-Scope Component Results", ""])
    for item in [result for result in scan.results if result.component.scope != "excluded"]:
        component = item.component
        lines.extend([
            f"### {component.name} {component.version or ''}".rstrip(), "",
            f"- Status: {item.status}", f"- Type: {component.component_type}",
            f"- Scope: {component.scope}",
            f"- Identifier: `{component.purl or component.cpe or 'none'}`",
        ])
        if item.message:
            lines.append(f"- Note: {item.message}")
        lines.append("")
        if item.vulnerabilities:
            lines.extend([
                "| KEV | Vulnerability | Severity | CVSS | EPSS | Fixed version | Source | Summary |",
                "|:---:|---|---:|---:|---:|---|---|---|",
            ])
            for vuln in item.vulnerabilities:
                summary = vuln.summary.replace("|", "\\|").replace("\n", " ")
                epss = f"{vuln.epss * 100:.2f}%" if vuln.epss is not None else "-"
                lines.append(
                    f"| {'YES' if vuln.kev else ''} | {vuln.id} | {vuln.severity} | "
                    f"{vuln.score if vuln.score is not None else '-'} | {epss} | "
                    f"{vuln.fixed_version or '-'} | {vuln.source} | {summary} |"
                )
            lines.append("")
            for vuln in item.vulnerabilities:
                if len(vuln.aliases) > 1:
                    aliases = ", ".join(f"`{alias}`" for alias in vuln.aliases)
                    lines.append(f"- `{vuln.id}` aliases: {aliases}")
            lines.append("")
    excluded_results = [result for result in scan.results if result.component.scope == "excluded"]
    if excluded_results:
        lines.extend(["## Excluded Component Results", "", "> These components are reported separately and are not included in the primary risk totals.", ""])
        for item in excluded_results:
            component = item.component
            lines.extend([f"### {component.name} {component.version or ''}".rstrip(), "", f"- Status: {item.status}", f"- Identifier: `{component.purl or component.cpe or 'none'}`", ""])
            if item.vulnerabilities:
                lines.append("- Findings: " + ", ".join(vuln.id for vuln in item.vulnerabilities))
                lines.append("")
    return "\n".join(lines)
