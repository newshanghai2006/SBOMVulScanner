from __future__ import annotations

from collections import Counter

from .models import ScanResult, Vulnerability


PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
STATUS_LABELS = {"vulnerable": "发现风险", "clean": "未命中", "unknown": "待确认", "error": "查询失败"}


def _cell(value: object | None) -> str:
    return str(value if value not in {None, ""} else "-").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _code(value: object | None) -> str:
    return f"`{str(value if value not in {None, ''} else '-').replace('`', '')}`"


def _short(value: str, limit: int = 180) -> str:
    clean = " ".join(value.split())
    return clean if len(clean) <= limit else clean[:limit - 1] + "..."


def _priority(vuln: Vulnerability) -> tuple[str, str]:
    if vuln.kev or vuln.severity == "CRITICAL":
        return "P0", "24 小时内确认并处置"
    if vuln.severity == "HIGH":
        return "P1", "7 天内完成升级或缓解"
    if vuln.severity == "MEDIUM":
        return "P2", "30 天内纳入修复计划"
    return "P3", "维护周期内复核"


def _epss(vuln: Vulnerability) -> str:
    return f"{vuln.epss * 100:.2f}%" if vuln.epss is not None else "-"


def _risk_conclusion(scan: ScanResult, active_vulns: list[Vulnerability], failed: int) -> str:
    if failed:
        return f"发现 {failed} 个组件查询失败，当前结果不完整，不能据此证明其余组件无漏洞。"
    if scan.kev_count:
        return f"命中 {scan.kev_count} 条 CISA KEV 已知在野利用记录，应立即确认暴露面并优先处置。"
    severe = sum(vuln.severity in {"CRITICAL", "HIGH"} for vuln in active_vulns)
    if severe:
        return f"命中 {severe} 条严重/高危风险记录，应优先升级存在修复版本且网络可达的组件。"
    if active_vulns:
        return "已发现公开漏洞匹配，建议结合部署环境、调用可达性和厂商公告安排修复。"
    return "当前可用数据源未命中已知漏洞；该结论不等同于组件绝对安全。"


def markdown_report(scan: ScanResult) -> str:
    active = [item for item in scan.results if item.component.scope != "excluded"]
    excluded = [item for item in scan.results if item.component.scope == "excluded"]
    findings = [(item, vuln) for item in active for vuln in item.vulnerabilities]
    active_vulns = [vuln for _, vuln in findings]
    failed = sum(item.status == "error" for item in active)
    pending = sum(item.status == "unknown" for item in active)
    clean = [item for item in active if item.status == "clean"]
    severity = Counter(vuln.severity for vuln in active_vulns)
    exact = sum(bool(item.component.version and (item.component.purl or item.component.cpe)) for item in active)
    missing_version = sum(not item.component.version for item in active)
    missing_identifier = sum(not (item.component.purl or item.component.cpe) for item in active)
    local_matches = sum("LocalIntel" in vuln.source for vuln in active_vulns)

    lines = [
        "# SBOM 漏洞扫描与风险分析报告", "",
        "## 1. 报告摘要", "",
        "| 项目 | 结果 |", "|---|---|",
        f"| 扫描对象 | {_code(scan.document_name)} |",
        f"| 文档类型 | {_cell(scan.document_type.upper())} |",
        f"| 扫描时间 | {_cell(scan.scanned_at)} |",
        f"| 文件 SHA-256 | {_code(scan.document_hash or '未记录')} |",
        f"| 扫描引擎 | {_cell(', '.join(scan.engines))} |",
        f"| 组件总数 | {scan.total_components} |",
        f"| 范围内风险组件 | {scan.vulnerable_components} |",
        f"| 范围内漏洞记录 | {scan.vulnerability_count} |",
        f"| 严重性分布 | CRITICAL {severity['CRITICAL']} / HIGH {severity['HIGH']} / MEDIUM {severity['MEDIUM']} / LOW {severity['LOW']} / UNKNOWN {severity['UNKNOWN']} |",
        f"| CISA KEV | {scan.kev_count} |",
        f"| 已知修复版本 | {scan.fixable_count} |",
        f"| 待确认 / 查询失败 | {pending} / {failed} |",
        f"| Excluded 组件 / 漏洞 | {scan.excluded_components} / {scan.excluded_vulnerability_count} |",
        f"| 本地人工情报命中 | {local_matches} |",
        f"| 主要结论 | {_cell(_risk_conclusion(scan, active_vulns, failed))} |", "",
        "> 数据库命中表示潜在暴露，不直接等同于实际可利用。最终处置应结合部署环境、调用路径、厂商公告和 VEX 复核。", "",
    ]

    if scan.warnings:
        lines.extend(["### 扫描告警", "", *[f"- {_cell(warning)}" for warning in scan.warnings], ""])
    if scan.ai_summary:
        lines.extend(["### AI 处置摘要（辅助信息）", "", scan.ai_summary, "", "> AI 摘要不改变正式漏洞数量、严重性或命中状态。", ""])

    lines.extend(["## 2. 风险概览与处置优先级", ""])
    if findings:
        lines.extend([
            "| 优先级 | 组件及版本 | 漏洞 | 评级 | KEV | EPSS | 修复版本 | 建议时限 |",
            "|---|---|---|---|:---:|---:|---|---|",
        ])
        ranked = sorted(findings, key=lambda pair: (
            PRIORITY_ORDER[_priority(pair[1])[0]], SEVERITY_ORDER.get(pair[1].severity, 4),
            -(pair[1].epss or 0), pair[1].id, pair[0].component.name,
        ))
        for item, vuln in ranked:
            priority, deadline = _priority(vuln)
            component = f"{item.component.name} {item.component.version or 'UNKNOWN'}"
            score = f"{vuln.severity} / CVSS {vuln.score}" if vuln.score is not None else vuln.severity
            lines.append(
                f"| {priority} | {_code(component)} | {_code(vuln.id)} | {_cell(score)} | "
                f"{'YES' if vuln.kev else '-'} | {_epss(vuln)} | {_code(vuln.fixed_version)} | {deadline} |"
            )
    else:
        lines.append("本次扫描未产生范围内的已知漏洞匹配记录。")
    lines.append("")

    lines.extend(["## 3. 已匹配漏洞详情", ""])
    if findings:
        for number, (item, vuln) in enumerate(ranked, 1):
            component = item.component
            priority, deadline = _priority(vuln)
            lines.extend([
                f"### 3.{number} {vuln.id}：{component.name} {component.version or 'UNKNOWN'}", "",
                "**组件定位**", "",
                f"- 组件：{_code(component.name)}",
                f"- 安装版本：{_code(component.version or 'UNKNOWN')}",
                f"- 标识：{_code(component.purl or component.cpe or '无可靠标识')}",
                f"- Scope：{_code(component.scope)}",
                f"- 数据源：{_cell(vuln.source)}", "",
                "**风险信号**", "",
                f"- 优先级：**{priority}**（{deadline}）",
                f"- 严重性 / CVSS：**{vuln.severity}** / {vuln.score if vuln.score is not None else '-'}",
                f"- CISA KEV：{'是' if vuln.kev else '否'}",
                f"- EPSS：{_epss(vuln)}",
                f"- 首个已知修复版本：{_code(vuln.fixed_version or '未提供')}",
                f"- 发布时间 / 更新时间：{_cell(vuln.published)} / {_cell(vuln.modified)}", "",
                "**公开摘要**", "", _cell(vuln.summary or "数据源未提供摘要。"), "",
            ])
            if len(vuln.aliases) > 1:
                lines.extend(["**关联标识**", "", "- " + ", ".join(_code(alias) for alias in vuln.aliases), ""])
            lines.extend(["**处置建议**", ""])
            if vuln.fixed_version:
                lines.append(f"1. 评估并升级到 {_code(vuln.fixed_version)} 或厂商支持的更高安全版本。")
            else:
                lines.append("1. 核验厂商公告和维护分支；当前数据源未提供明确修复版本。")
            lines.extend([
                "2. 确认组件在实际构建产物中的最终解析版本，并检查漏洞相关功能是否可由不可信输入触达。",
                "3. 升级后重新生成 SBOM 并复扫；如判定不可利用，应记录技术依据、适用版本和复核期限。", "",
            ])
            if vuln.references:
                lines.extend(["**参考来源**", "", *[f"- <{url}>" for url in vuln.references], ""])
    else:
        lines.extend(["无范围内漏洞详情。", ""])

    lines.extend(["## 4. 新兴威胁情报（未验证）", ""])
    if scan.emerging_threats:
        lines.extend([
            "> 本节来自可选的 AI Web 搜索，不计入正式漏洞统计；必须人工核验原始来源和受影响版本。", "",
            "| 置信度 | 组件 | 安装版本 | 版本声明 | 标识 | 来源 | 匹配理由 |",
            "|---|---|---|---|---|---|---|",
        ])
        for threat in scan.emerging_threats:
            identifiers = ", ".join(threat.identifiers) or "无标准编号"
            lines.append(
                f"| {threat.confidence.upper()} | {_code(threat.component_purl)} | {_cell(threat.installed_version)} | "
                f"{_cell(threat.affected_version_claim)} | {_cell(identifiers)} | [{_cell(threat.title)}]({threat.source_url}) | {_cell(threat.reason)} |"
            )
    else:
        lines.append("未启用 AI 新兴威胁搜索，或本次搜索没有保留符合证据要求的结果。")
    lines.append("")

    lines.extend([
        "## 5. SBOM 完整性与未命中边界", "",
        "| 指标 | 数量 | 含义 |", "|---|---:|---|",
        f"| 具备版本和 purl/CPE | {exact} | 可执行较可靠的精确版本查询 |",
        f"| 缺少版本 | {missing_version} | 无法可靠判断受影响版本范围 |",
        f"| 缺少 purl/CPE | {missing_identifier} | 无法可靠映射公开漏洞包或硬件产品 |",
        f"| 当前数据源未命中 | {len(clean)} | 仅表示本次公开数据没有返回匹配，不等于绝对安全 |",
        f"| 待确认 / 查询失败 | {pending} / {failed} | 需要补全 SBOM 或恢复数据源后复扫 |", "",
    ])
    uncertain = [item for item in active if item.status in {"unknown", "error"}]
    if uncertain:
        lines.extend(["### 待确认或查询失败组件", "", "| 组件 | 版本 | 标识 | 状态 | 原因 |", "|---|---|---|---|---|"])
        for item in uncertain:
            lines.append(
                f"| {_cell(item.component.name)} | {_cell(item.component.version)} | "
                f"{_code(item.component.purl or item.component.cpe)} | {STATUS_LABELS[item.status]} | {_cell(item.message)} |"
            )
        lines.append("")

    lines.extend(["### 未命中组件", ""])
    if clean:
        lines.extend(["| 组件 | 版本 | 标识 |", "|---|---|---|"])
        for item in clean:
            lines.append(f"| {_cell(item.component.name)} | {_cell(item.component.version)} | {_code(item.component.purl or item.component.cpe)} |")
    else:
        lines.append("无。")
    lines.append("")

    lines.extend(["## 6. Excluded Scope 结果", "", "> 本节不计入主要生产风险总数，但仍保留供审计和范围复核。", ""])
    if excluded:
        lines.extend(["| 组件 | 版本 | 状态 | 漏洞 | 标识 |", "|---|---|---|---|---|"])
        for item in excluded:
            vuln_ids = ", ".join(vuln.id for vuln in item.vulnerabilities) or "-"
            lines.append(
                f"| {_cell(item.component.name)} | {_cell(item.component.version)} | {STATUS_LABELS[item.status]} | "
                f"{_cell(vuln_ids)} | {_code(item.component.purl or item.component.cpe)} |"
            )
    else:
        lines.append("无 Excluded scope 组件。")
    lines.append("")

    p0 = sum(_priority(vuln)[0] == "P0" for vuln in active_vulns)
    p1 = sum(_priority(vuln)[0] == "P1" for vuln in active_vulns)
    lines.extend([
        "## 7. 推荐实施顺序", "",
        "| 阶段 | 动作 | 验收标准 |", "|---|---|---|",
        f"| 立即 | 复核并处置 P0 记录（{p0} 条），确认 KEV 和互联网暴露面 | P0 有升级、缓解或有期限的 VEX 结论 |",
        f"| 7 天内 | 处理 P1 高危记录（{p1} 条），优先采用已知修复版本 | 构建产物不再包含受影响版本，回归测试通过 |",
        f"| 30 天内 | 处理 P2/P3，并补全 {missing_version + missing_identifier} 个标识或版本缺口 | 待确认项显著减少，例外项有责任人和期限 |",
        "| 持续 | 每次发布重建 SBOM，并定期复扫 | SBOM 与发布物一一对应，可追溯到构建版本 |", "",
        "## 8. 扫描方法与判定边界", "",
        f"- 使用引擎：{_cell(', '.join(scan.engines))}。",
        f"- 数据新鲜度声明：{_cell(scan.data_freshness)}。",
        "- OSV/NVD/Trivy 命中依据组件 purl、CPE、名称和精确版本；错误标识可能导致误报或漏报。",
        "- EPSS 是未来利用概率预测，KEV 表示已知在野利用；二者用于排序，不替代实际环境验证。",
        "- 数据源失败始终标记为查询失败，不解释为未发现漏洞。",
        "- 最终处置应结合厂商公告、补丁状态、部署环境、调用可达性和 VEX 复核。", "",
        "## 9. 参考资料", "",
    ])
    references = list(dict.fromkeys(
        url for vuln in active_vulns for url in vuln.references
    ))
    references.extend(threat.source_url for threat in scan.emerging_threats if threat.source_url not in references)
    if references:
        lines.extend(f"- <{url}>" for url in references)
    else:
        lines.extend([
            "- OSV：<https://osv.dev/>",
            "- CISA KEV：<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>",
            "- FIRST EPSS：<https://www.first.org/epss/>",
        ])
    lines.extend([
        "", "---", "",
        "> 本报告反映扫描时可用数据源的匹配结果。依赖、构建产物、运行配置或漏洞数据库变化后，应重新生成 SBOM 并复扫。", "",
    ])
    return "\n".join(lines)
