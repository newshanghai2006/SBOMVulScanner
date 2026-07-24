# SBOM Scan

轻量的 SBOM/HBOM Web 漏洞治理工具。软件组件通过 OSV 批量接口匹配，硬件 CPE 通过 NVD 匹配；可选使用 Trivy 补充操作系统包、供应商公告和容器镜像漏洞。结果使用 FIRST EPSS 与 CISA KEV 增强，并保存到本地 SQLite。

## 功能

- 支持 CycloneDX JSON 1.4+、SPDX JSON 2.x 和本项目 HBOM JSON。
- 使用 Syft 从源码 ZIP 或受控 Git 仓库生成 CycloneDX/SPDX JSON，并直接下载。
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

## 从源码生成 SBOM

源码生成是漏洞扫描前的独立步骤，使用 Syft 分析依赖清单和软件包元数据，不需要 LLM Base URL、API Key 或模型。支持以下输入：

- 不超过 1000 MB 的源码 ZIP；解压后最多 100,000 个文件、3000 MB。
- 受控的 `git clone` 命令，例如 `git clone -b release --single-branch http://10.1.1.1:3000/group/project.git`。

Git 命令只接受 `-b/--branch` 和 `--single-branch`，不接受目标目录或其他 Git 参数。服务端不会通过 shell 执行输入，而是强制浅克隆到随机临时目录。ZIP 路径穿越和符号链接会被拒绝；Git 元数据会在分析前删除。请求完成后，上传内容、仓库工作区和生成文件都会从服务端临时目录删除。

粘贴 Git 命令时，页面只读取纯文本并限制为 4,096 个字符。选择“公开仓库”时执行严格的非交互匿名克隆；选择“私有仓库”时页面会在发送生成请求前立即弹出认证窗口，可输入用户名和密码或 Personal Access Token。若公开模式被仓库拒绝，401 响应仍会自动切换到私有模式并弹窗。服务器全局 Git credential helper 始终禁用，避免后台认证窗口让请求长时间挂起。认证信息通过一次性 Git AskPass 传递，不进入 Git 命令行、仓库 URL、日志、SQLite 或报告，克隆结束后立即清除。SSH 仓库不使用浏览器认证，应为运行服务的专用账号配置只读 SSH key。

可输出并下载：

- CycloneDX JSON，文件名以 `.cdx.json` 结尾。
- SPDX JSON，文件名以 `.spdx.json` 结尾。

生成成功后，页面会把 SBOM 自动放入下方“选择清单”，自动选择 CycloneDX/SPDX 类型并滚动到扫描区域，可以直接点击“开始扫描”，无需先下载再重新上传。生成结果的“下载 SBOM”按钮仍然保留。

ZIP 采用分块方式写入临时文件，不会一次性把整个 1000 MB 上传内容读入 Python 内存。生成期间需要同时容纳压缩包、最多 3000 MB 的源码目录和 Syft 输出，建议临时磁盘至少保留 5 GB 可用空间。Git 克隆最长等待 15 分钟，Syft 分析最长等待 30 分钟。

## openEuler 24.03 安装与运行

以下命令面向 openEuler 24.03。建议使用普通用户安装和运行，不要使用 `root`，也不要把项目目录与其他用户共享。项目自己的 `.venv` 会隔离 Python 包，避免修改系统 Python 或其他人的虚拟环境。

```bash
sudo dnf install -y python3 python3-pip git curl ca-certificates

git clone <your-repository-url> sbom-scan
cd sbom-scan
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
chmod +x start.sh start-public.sh stop.sh
```

源码 SBOM 生成功能还需要 Syft。生产环境应先审查安装脚本，或从 Anchore 官方发布页下载并校验固定版本：

```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
syft version
```

若 `python3 -m venv` 提示缺少 `ensurepip`，请先确认系统软件源已启用并重新安装 Python/Pip。若依赖需要本机编译，再安装构建工具：

```bash
sudo dnf install -y python3-devel gcc gcc-c++ make
```

### SSH 登录场景（推荐）

启动脚本默认监听 `127.0.0.1:8088`，通过 `nohup` 在后台运行。SSH 断开不会终止服务。若要使用 Git 仓库输入，必须显式配置允许的仓库主机，多个主机使用逗号分隔：

```bash
cd /data/strix/sbom-scan
SBOM_GIT_ALLOWED_HOSTS=10.1.1.1,git.example.com ./start.sh
cat data/server-state.json
curl http://127.0.0.1:8088/api/health
```

在自己的电脑上建立 SSH 隧道（将用户名和服务器地址替换为实际值）：

```bash
ssh -L 8088:127.0.0.1:8088 username@server-address
```

保持该 SSH 窗口连接，然后在本机浏览器打开 `http://127.0.0.1:8088`。这种方式无需开放服务器防火墙端口，其他网络用户也不能直接访问 Web 服务。

查看日志和安全停止：

```bash
tail -f data/server.out.log data/server.err.log
./stop.sh
```

`start.sh` 强制使用当前项目的 `.venv/bin/python`，不会退回系统 Python。`stop.sh` 只读取本项目的 `data/server.pid`，并校验目标进程的 Uvicorn 命令行和 `/proc/<PID>/cwd` 都属于当前项目后才停止。它不会执行 `pkill python` 或 `killall python`，因此不会结束其他用户或其他项目的 Python 进程。不要手工修改或与其他项目共用 `data/server.pid`。

需要改用其他端口时，启动和 SSH 隧道中的端口必须一致：

```bash
PORT=8090 ./start.sh
ssh -L 8090:127.0.0.1:8090 username@server-address
```

仅当确实需要让局域网用户直接访问时，使用公共监听启动脚本。该脚本固定监听 `0.0.0.0:8088`，停止仍使用 `stop.sh`：

```bash
SBOM_GIT_ALLOWED_HOSTS=10.1.1.1,git.example.com ./start-public.sh
sudo firewall-cmd --permanent --add-port=8088/tcp
sudo firewall-cmd --reload

# 停止服务
./stop.sh
```

`SBOM_GIT_ALLOWED_HOSTS` 按主机名或 IP 精确匹配，不填写时禁用所有 Git 仓库输入，但 ZIP 生成仍可使用。不要在 HTTP(S) URL 中写密码；应在页面选择“私有仓库”并通过认证弹窗输入。SSH 仓库应为运行服务的专用普通用户配置只读 SSH key。

主机白名单与仓库认证是两层独立控制。出现 `仓库主机未被服务器管理员允许` 时，认证弹窗不会绕过该限制。例如允许 `10.1.1.1`：

```bash
cd /data/strix/sbom-scan
./stop.sh
SBOM_GIT_ALLOWED_HOSTS=10.1.1.1 ./start-public.sh
```

重启后再次生成：在 Git 输入区选择“私有仓库”，页面会立即弹出认证窗口。使用令牌时，“用户名”填写该 Git 平台要求的用户名，“密码或访问令牌”填写令牌。认证页面应通过 HTTPS 或本机 SSH 隧道访问，避免凭据在网络中明文传输。

监听 `0.0.0.0` 会扩大暴露面，源码生成又会消耗 CPU、内存和网络资源。正式环境应使用 Nginx/Caddy 配置 HTTPS、身份认证、请求大小限制和访问控制，并在不再需要外部访问时删除防火墙规则。若使用 Nginx，需将 `client_max_body_size` 配置为至少 `1000m`，否则请求会在到达程序前被 Nginx 拒绝。

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
.\start.ps1                  # 默认 127.0.0.1:8088
.\start.ps1 -Port 8090       # 指定固定端口
.\stop.ps1                   # 只关闭 start.ps1 记录的本项目进程
```

### Windows 配置 Git 仓库主机白名单

出现 `仓库主机 '10.1.1.1' 未被服务器管理员允许` 时，需要先停止现有服务，再把该主机传给本项目启动脚本：

```powershell
cd D:\path\to\sbom-scan
.\stop.ps1
.\start.ps1 -GitAllowedHosts "10.1.1.1"
```

多个仓库主机使用英文逗号分隔：

```powershell
.\stop.ps1
.\start.ps1 -GitAllowedHosts "10.1.1.1,git.example.com"
```

`-GitAllowedHosts` 只设置本次启动的 SBOM Scan 子进程，不修改其他用户、其他终端或其他 Python 进程。服务已经运行时必须先执行 `stop.ps1`，否则 `start.ps1` 会保留原进程，新的白名单不会生效。

也可以在当前 PowerShell 窗口中临时设置环境变量。该变量会被随后启动的 SBOM Scan 继承，关闭 PowerShell 后失效：

```powershell
.\stop.ps1
$env:SBOM_GIT_ALLOWED_HOSTS = "10.1.1.1"
.\start.ps1
```

需要对当前 Windows 用户持久保存时：

```powershell
[Environment]::SetEnvironmentVariable(
    "SBOM_GIT_ALLOWED_HOSTS",
    "10.1.1.1,git.example.com",
    "User"
)
```

设置后关闭并重新打开 PowerShell，再执行 `stop.ps1` 和 `start.ps1`。删除用户级配置：

```powershell
[Environment]::SetEnvironmentVariable("SBOM_GIT_ALLOWED_HOSTS", $null, "User")
```

如果需要让其他计算机直接访问 Windows 上的服务，可同时指定监听地址；还需按组织安全策略配置 Windows 防火墙：

```powershell
.\stop.ps1
.\start.ps1 -HostAddress "0.0.0.0" -Port 8088 -GitAllowedHosts "10.1.1.1"
```

白名单只允许服务器连接指定 Git 主机，不等于仓库身份认证。主机允许后，在 Git 输入区主动选择“私有仓库”，认证窗口会在生成请求发出前弹出；如果误选“公开仓库”，认证失败后也会自动弹窗。

也可以按端口强制停止任意 TCP 监听进程：

```bat
stop.bat 8088
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
./start.sh
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
3. 上传不超过 100 MB 的 JSON 文件；从源码生成的 SBOM 会自动进入此选择清单。
4. 高级配置始终显示，可按需选择扫描引擎、容器扫描、NVD key 或 LLM。
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
