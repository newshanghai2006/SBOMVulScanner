# SBOM Scan

轻量的 SBOM/HBOM Web 漏洞治理工具。软件组件通过 OSV 批量接口匹配，硬件 CPE 通过 NVD 匹配；可选使用 Trivy 补充操作系统包、供应商公告和容器镜像漏洞。结果使用 FIRST EPSS 与 CISA KEV 增强，并保存到本地 SQLite。

## 功能

- 支持 CycloneDX JSON 1.4+、SPDX JSON 2.x 和本项目 HBOM JSON。
- 使用 CVE/GHSA/OSV 别名归并重复记录。
- 解析 CVSS、OSV 版本区间和与当前版本对应的最小修复版本。
- 使用成熟的生态版本规则比较 PyPI、npm、Maven、Go、Cargo、NuGet、RubyGems、Composer、Debian、RPM 和 Alpine 版本。
- 按 `CISA KEV -> 严重性 -> EPSS` 排序。
- 将 CycloneDX `scope: excluded` 独立统计，不计入主要生产风险。
- 可选 Trivy 混合扫描和容器镜像扫描。
- SQLite 保存历史结果；不保存上传的原始清单或 API key。
- 导出 Markdown 报告；数据源失败与“未发现漏洞”严格区分。

## 支持格式

### CycloneDX

读取 `components[].name/version/purl/cpe/scope` 和组件类型。软件组件应提供准确的 purl，容器应尽量使用不可变 digest，例如：

```json
{
  "type": "container",
  "name": "registry.example.com/team/app@sha256:...",
  "version": "sha256:...",
  "scope": "required"
}
```

`scope` 的处理规则：

- `required`、`optional` 或缺失：计入主要风险统计。
- `excluded`：仍会扫描，但只出现在 Excluded 指标、筛选和报告章节中。

### SPDX

读取 `packages[]` 以及 `externalRefs` 中的 purl/CPE。SPDX 2.x 没有与 CycloneDX 完全等价的组件 scope，因此导入后标记为 `unknown`，并计入主要统计。

### HBOM

项目定义格式见 `examples/hbom-example.json`。每个组件必须有 `name`；可靠扫描还必须提供标准 CPE 2.3。只有厂商和型号、没有 CPE 的组件会标为“待确认”，不会猜测匹配。

## Linux 安装

推荐 Python 3.11 或 3.12。以下命令适用于 Ubuntu/Debian：

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl ca-certificates

git clone <your-repository-url> sbom-scan
cd sbom-scan
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

推荐使用启动脚本，默认固定监听 `127.0.0.1:8000`：

```bash
chmod +x start.sh stop.sh
./start.sh
./stop.sh
```

需要使用其他固定端口时：

```bash
PORT=8080 ./start.sh
```

也可以手工启动开发或内网服务：

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

仅在确实需要局域网访问时监听所有网卡，并通过防火墙或反向代理限制来源：

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

浏览器访问 `http://127.0.0.1:8000`。生产部署建议在 Nginx/Caddy 后运行 Uvicorn，并使用 systemd 或其他进程管理器保持服务运行。

## Windows 安装

在 PowerShell 中安装依赖：

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

如果执行策略阻止激活脚本，可以直接运行：

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

推荐使用固定端口启动和 PID 安全关闭脚本：

```powershell
.\start.ps1                  # 默认 127.0.0.1:8000
.\start.ps1 -Port 8080       # 指定固定端口
.\stop.ps1                   # 只关闭 start.ps1 记录的本项目进程
```

也可以按端口强制停止任意 TCP 监听进程：

```bat
stop.bat 8000
```

`stop.bat` 会显示监听进程后执行 `taskkill /F`。它不校验该进程是否属于 SBOM Scan，因此使用前必须确认端口正确；权限不足时需要以管理员身份运行。

## 安装 Trivy（可选）

不安装 Trivy 时，OSV/NVD、EPSS、KEV、历史记录和报告功能仍可使用。

Linux 可使用 Trivy 官方安装脚本。生产环境应先审查脚本或按 Trivy 官方文档配置软件源：

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin
trivy --version
```

Windows 可使用 WinGet：

```powershell
winget install AquaSecurity.Trivy
trivy --version
```

如果 Trivy 不在 `PATH`，可指定完整路径：

```bash
export TRIVY_PATH=/opt/trivy/bin/trivy
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## 扫描引擎

高级配置中可以选择：

- **自动检测**：检测到 Trivy 时使用混合模式，否则使用 OSV/NVD。
- **仅 OSV / NVD**：不调用本机 Trivy，适合最轻量部署。
- **OSV / NVD + Trivy**：同时运行两种来源并归并结果；Trivy 缺失或失败时显示明确告警。

“扫描容器镜像”默认关闭。开启后，程序会让 Trivy 拉取并扫描 SBOM 中最多 5 个 `type: container` 的镜像。该操作可能下载大量数据，并会访问镜像仓库。

私有仓库建议先使用 Trivy 登录，避免把凭据放入 SBOM：

```bash
printf '%s' "$REGISTRY_PASSWORD" | trivy registry login \
  --username "$REGISTRY_USERNAME" --password-stdin registry.example.com
```

应用通过参数数组调用 Trivy，不使用 shell；镜像引用还会经过字符白名单校验。Trivy 错误不会被解释为“镜像无漏洞”。

## 使用

1. 打开 Web 页面。
2. 选择自动识别、CycloneDX、SPDX 或 HBOM。
3. 上传不超过 5 MB 的 JSON 文件。
4. 按需展开高级配置，选择扫描引擎、容器扫描、NVD key 或 LLM。
5. 扫描后按风险状态或 Excluded scope 筛选，并下载 Markdown 报告。
6. 最近扫描保存在本机，可以重新打开或删除。

扫描历史位于 `data/sbom-scan.db`，该目录已加入 `.gitignore`。删除数据库即可清空全部历史。文件中只保存扫描结果和输入文件 SHA-256，不保存原始 SBOM/HBOM、NVD key 或 LLM key。

## AI / LLM 配置

AI 功能默认全部关闭，并且永远不参与正式漏洞命中判定。高级配置提供两个相互独立的开关。

### AI 处置摘要

只总结 OSV、NVD 和 Trivy 已确认的结构化结果。接口需兼容 OpenAI `POST /chat/completions`：

```text
发送：非 excluded 风险组件名、版本、漏洞 ID、严重性和 KEV 状态
返回：中文风险优先级和处置建议
```

若 Base URL 为 `https://host/v1`，程序请求 `https://host/v1/chat/completions`。摘要不改变漏洞数量、严重性或研判状态。

### AI 新兴威胁搜索

使用 OpenAI Responses API 的 `web_search` 工具搜索近期公开披露。模型服务必须支持：

```http
POST /v1/responses
```

请求使用：

```json
{
  "tools": [{"type": "web_search"}]
}
```

官方接口说明：<https://developers.openai.com/api/docs/guides/tools-web-search>

普通的 OpenAI-compatible `/chat/completions` 服务不一定支持 Responses 或实时搜索。若服务不兼容，扫描仍会保留正式 OSV/NVD/Trivy 结果，并在页面和报告中显示 AI 搜索失败告警。

搜索规则：

- 仅发送非 `excluded` 且带 purl 的组件。
- 默认最多搜索 10 个组件，允许配置 1～20 个。
- 默认搜索最近 30 天，允许配置 1～365 天。
- 优先选择序列化、网络、认证、加密、Web 框架等安全敏感组件。
- 每 5 个组件组成一个请求批次，以限制单次上下文和费用。
- 网页内容被视为不可信数据；提示明确禁止遵循网页中的命令或指令。
- 只有 purl 精确匹配且来源 URL 出现在 Responses citation annotations 中的结果才会保留。
- 没有明确版本证据时不得判定当前版本受影响。
- 新兴情报始终标记为 `unverified`，不计入正式漏洞数量、KEV、严重性或策略统计。

搜索结果只保存标题、引用 URL、发布时间声明、版本声明、标识符、置信度和匹配理由，不保存网页全文。LLM API key、NVD key 及搜索凭据不保存到 SQLite 或报告。

启用实时搜索意味着组件名称、版本和 purl 会发送给所配置的模型服务。包含内部包名的 SBOM 应先评估数据外发政策，或使用企业内部支持 Responses Web Search 的服务。

### 人工确认并加入本地情报库

每条 AI 新兴威胁结果都提供“确认并加入本地库”按钮。点击后会再次显示组件、精确安装版本和原始来源，只有人工确认后才写入 SQLite。

确认记录包含：

```text
LOCAL 编号
组件基础 purl
精确安装版本
来源 URL
来源标题和匹配理由
来源明确给出的 CVE/GHSA 等标识
确认时间
```

为避免从文章标题错误推断版本范围，本地记录首版只匹配确认时的精确版本。例如确认 `pkg:maven/com.alibaba/fastjson@1.2.83` 后：

- 后续扫描 `1.2.83` 会命中 `LocalIntel`。
- `1.2.82`、`1.2.84` 不会被推断为受影响。
- 如果记录包含已存在的 CVE/GHSA，会与官方结果合并来源而不重复计数。
- 没有标准编号时使用独立的 `LOCAL-...` 编号，严重性保持 `UNKNOWN`。

页面顶部的“本地情报库”列出所有人工记录并支持删除。新增记录从下一次扫描开始生效；删除后不会影响已保存的历史报告，但不再参与后续扫描。

本地情报属于组织自己的人工判断，不代表 OSV、NVD、CISA 或厂商正式确认。报告会通过 `LocalIntel` 来源明确区分。

## 测试

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## 判定边界

- 数据库命中代表潜在暴露，不等于漏洞在实际部署中可利用。
- 容器组件只有名称时，普通 SBOM 扫描无法看到镜像内部软件包；需要启用容器镜像扫描或上传包含 OS 包的完整镜像 SBOM。
- EPSS/KEV 获取失败不影响主扫描，但对应风险信号会留空。
- Trivy、OSV、NVD 的更新时间和覆盖范围不同，混合模式结果可能比单一引擎更多。
- 最终处置应结合厂商公告、补丁状态、部署环境、调用可达性和 VEX 复核。
