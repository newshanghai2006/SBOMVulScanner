const form = document.querySelector('#scanForm');
const input = document.querySelector('#fileInput');
const dropzone = document.querySelector('#dropzone');
const errorBox = document.querySelector('#error');
const progress = document.querySelector('#progress');
const button = document.querySelector('#scanButton');
const resultsSection = document.querySelector('#results');
const componentList = document.querySelector('#componentList');
let currentResults = [];
let currentThreats = [];
let activeFilter = 'all';

const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

function showFile(file) {
  if (!file) return;
  document.querySelector('#fileTitle').textContent = file.name;
  document.querySelector('#fileMeta').textContent = `${(file.size / 1024).toFixed(1)} KB · 准备扫描`;
  dropzone.classList.add('has-file');
}

input.addEventListener('change', () => showFile(input.files[0]));
['dragenter', 'dragover'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.add('dragging'); }));
['dragleave', 'drop'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.remove('dragging'); }));
dropzone.addEventListener('drop', event => {
  if (!event.dataTransfer.files.length) return;
  const transfer = new DataTransfer(); transfer.items.add(event.dataTransfer.files[0]); input.files = transfer.files; showFile(input.files[0]);
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  errorBox.hidden = true; progress.hidden = false; button.disabled = true;
  button.querySelector('span').textContent = '正在匹配漏洞';
  try {
    const response = await fetch('/api/scan', { method: 'POST', body: new FormData(form) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || '扫描请求失败');
    renderResult(data);
    loadHistory();
  } catch (error) {
    errorBox.textContent = error.message; errorBox.hidden = false;
  } finally {
    progress.hidden = true; button.disabled = false; button.querySelector('span').textContent = '开始扫描';
  }
});

function statusLabel(status) {
  return { vulnerable: '发现风险', clean: '未命中', unknown: '待确认', error: '查询失败' }[status] || status;
}

function renderResult(data) {
  currentResults = data.results;
  document.querySelector('#resultName').textContent = data.document_name;
  document.querySelector('#scanTime').textContent = `${data.document_type.toUpperCase()} · ${new Date(data.scanned_at).toLocaleString('zh-CN')}`;
  document.querySelector('#totalCount').textContent = data.total_components;
  document.querySelector('#riskCount').textContent = data.vulnerable_components;
  document.querySelector('#vulnCount').textContent = data.vulnerability_count;
  document.querySelector('#unknownCount').textContent = data.results.filter(item => ['unknown', 'error'].includes(item.status)).length;
  document.querySelector('#kevCount').textContent = data.kev_count || 0;
  document.querySelector('#fixableCount').textContent = data.fixable_count || 0;
  document.querySelector('#excludedCount').textContent = data.excluded_vulnerability_count || 0;
  const warnings = document.querySelector('#scanWarnings');
  warnings.hidden = !(data.warnings || []).length;
  warnings.innerHTML = (data.warnings || []).map(message => `<p>${escapeHtml(message)}</p>`).join('');
  document.querySelector('#downloadReport').href = `/api/report/${data.scan_id}`;
  const ai = document.querySelector('#aiSummary');
  ai.hidden = !data.ai_summary; ai.querySelector('p').textContent = data.ai_summary || '';
  renderEmergingThreats(data.emerging_threats || []);
  resultsSection.hidden = false; renderComponents();
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderEmergingThreats(threats) {
  currentThreats = threats;
  const section = document.querySelector('#emergingThreats');
  section.hidden = threats.length === 0;
  document.querySelector('#emergingList').innerHTML = threats.map((item, index) => `
    <article class="emerging-item">
      <div><span class="unverified">未验证 · ${escapeHtml(item.confidence.toUpperCase())}</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.reason)}</p></div>
      <dl><div><dt>组件</dt><dd>${escapeHtml(item.component)} ${escapeHtml(item.installed_version || '')}</dd></div><div><dt>版本声明</dt><dd>${escapeHtml(item.affected_version_claim || '来源未给出明确范围')}</dd></div><div><dt>标识</dt><dd>${escapeHtml((item.identifiers || []).join(', ') || '尚无标准编号')}</dd></div></dl>
      <div class="emerging-actions"><a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer">查看原始来源</a><button data-confirm-threat="${index}" ${item.installed_version ? '' : 'disabled'}>确认并加入本地库</button></div>
    </article>`).join('');
}

document.querySelector('#emergingList').addEventListener('click', async event => {
  const button = event.target.closest('[data-confirm-threat]'); if (!button) return;
  const item = currentThreats[Number(button.dataset.confirmThreat)];
  if (!item || !item.installed_version) return;
  const confirmed = window.confirm(`确认将 ${item.component} ${item.installed_version} 作为精确版本漏洞加入本地库？\n\n来源：${item.source_url}\n\n该记录会参与后续扫描，但不会推断其他版本。`);
  if (!confirmed) return;
  button.disabled = true; button.textContent = '正在保存';
  const response = await fetch('/api/custom-advisories', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
      component_purl: item.component_purl, exact_version: item.installed_version,
      title: item.title, source_url: item.source_url, identifiers: item.identifiers || [],
      severity: 'UNKNOWN', reason: item.reason, confirmed: true,
    }),
  });
  if (response.ok) {
    button.textContent = '已加入 · 重新扫描后生效'; loadCustomAdvisories();
  } else {
    const error = await response.json(); button.disabled = false; button.textContent = error.detail || '保存失败';
  }
});

async function loadCustomAdvisories() {
  try {
    const response = await fetch('/api/custom-advisories'); if (!response.ok) return;
    const advisories = await response.json();
    const section = document.querySelector('#localIntelSection'); section.hidden = advisories.length === 0;
    document.querySelector('#localIntelCount').textContent = `${advisories.length} 条精确版本记录`;
    document.querySelector('#localIntelList').innerHTML = advisories.map(item => `
      <div class="local-intel-item" data-id="${escapeHtml(item.id)}"><div><span>${escapeHtml(item.id)} · ${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.component_purl)}@${escapeHtml(item.exact_version)}</small></div><a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer">来源</a><button class="local-intel-delete" title="删除本地情报" aria-label="删除 ${escapeHtml(item.id)}">×</button></div>`).join('');
  } catch (_) { /* Local intelligence management is non-critical to scanning. */ }
}

document.querySelector('#localIntelList').addEventListener('click', async event => {
  const button = event.target.closest('.local-intel-delete'); if (!button) return;
  const row = button.closest('.local-intel-item');
  if (!window.confirm('删除这条本地情报？后续扫描将不再匹配它。')) return;
  const response = await fetch(`/api/custom-advisories/${row.dataset.id}`, {method: 'DELETE'});
  if (response.ok) loadCustomAdvisories();
});

function renderComponents() {
  const term = document.querySelector('#search').value.trim().toLowerCase();
  const filtered = currentResults.filter(item => {
    const isExcluded = item.component.scope === 'excluded';
    const matchesFilter = activeFilter === 'excluded' ? isExcluded : !isExcluded && (activeFilter === 'all' || item.status === activeFilter || (activeFilter === 'unknown' && item.status === 'error'));
    const haystack = [item.component.name, item.component.version, item.component.purl, item.component.cpe, ...item.vulnerabilities.map(v => v.id)].join(' ').toLowerCase();
    return matchesFilter && haystack.includes(term);
  });
  componentList.innerHTML = filtered.map(item => {
    const c = item.component;
    const detail = item.vulnerabilities.length ? item.vulnerabilities.map(v => {
      const signals = [v.kev ? '<b class="kev-flag">CISA KEV</b>' : '', v.score == null ? '' : `CVSS ${v.score}`, v.epss == null ? '' : `EPSS ${(v.epss * 100).toFixed(2)}%`, v.fixed_version ? `修复版本 ${escapeHtml(v.fixed_version)}` : '暂无已知修复'].filter(Boolean).join('<span>·</span>');
      const aliases = (v.aliases || []).filter(id => id !== v.id).map(escapeHtml).join(' · ');
      return `<div class="vuln"><span class="vuln-id">${escapeHtml(v.id)}</span><span class="severity ${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span><div><div class="signals">${signals}</div><p>${escapeHtml(v.summary || '暂无漏洞摘要')}</p>${aliases ? `<small>别名：${aliases}</small>` : ''}</div></div>`;
    }).join('') : `<div class="notice">${escapeHtml(item.message || '在当前公开漏洞数据中未发现与该组件标识匹配的记录。')}</div>`;
    return `<details class="component">
      <summary><div class="component-name"><strong>${escapeHtml(c.name)} ${escapeHtml(c.version || '')}</strong><span>${escapeHtml(c.vendor || c.component_type)} · ${escapeHtml(c.scope || 'unknown')}</span></div><span class="identifier">${escapeHtml(c.purl || c.cpe || '无可靠标识')}</span><span class="badge ${item.status}">${c.scope === 'excluded' ? 'EXCLUDED · ' : ''}${statusLabel(item.status)}${item.vulnerabilities.length ? ` · ${item.vulnerabilities.length}` : ''}</span><svg class="chevron" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></summary>
      <div class="component-detail">${detail}</div></details>`;
  }).join('');
  document.querySelector('#empty').hidden = filtered.length !== 0;
}

document.querySelector('#filters').addEventListener('click', event => {
  const target = event.target.closest('button'); if (!target) return;
  activeFilter = target.dataset.filter; document.querySelectorAll('#filters button').forEach(btn => btn.classList.toggle('active', btn === target)); renderComponents();
});
document.querySelector('#search').addEventListener('input', renderComponents);

async function loadHistory() {
  try {
    const response = await fetch('/api/scans?limit=12');
    if (!response.ok) return;
    const scans = await response.json();
    const section = document.querySelector('#historySection');
    section.hidden = scans.length === 0;
    document.querySelector('#historyList').innerHTML = scans.map(scan => `
      <div class="history-item" data-id="${escapeHtml(scan.scan_id)}">
        <button class="history-open" title="打开历史扫描"><span><strong>${escapeHtml(scan.document_name)}</strong><small>${escapeHtml(scan.document_type.toUpperCase())} · ${new Date(scan.scanned_at).toLocaleString('zh-CN')}</small></span><span class="history-risk ${scan.vulnerable_components ? 'has-risk' : ''}">${scan.vulnerable_components} 风险组件${scan.kev_count ? ` · ${scan.kev_count} KEV` : ''}</span></button>
        <button class="history-delete" title="删除历史扫描" aria-label="删除 ${escapeHtml(scan.document_name)}">×</button>
      </div>`).join('');
  } catch (_) { /* History is non-critical to scanning. */ }
}

document.querySelector('#historyList').addEventListener('click', async event => {
  const row = event.target.closest('.history-item'); if (!row) return;
  if (event.target.closest('.history-delete')) {
    await fetch(`/api/scans/${row.dataset.id}`, { method: 'DELETE' }); loadHistory(); return;
  }
  if (event.target.closest('.history-open')) {
    const response = await fetch(`/api/scans/${row.dataset.id}`);
    if (response.ok) renderResult(await response.json());
  }
});

loadHistory();
loadCustomAdvisories();
