// SecOps Visual Lab - Frontend Logic
const API = "http://127.0.0.1:51234/api";
let scanPollTimer = null;

// ========== Page Navigation ==========
function switchPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav li').forEach(l => l.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.querySelector(`.nav[data-page="${name}"]`)?.classList.add('active');
  // sidebar nav
  document.querySelectorAll('.nav li').forEach(l => {
    if (l.dataset.page === name) l.classList.add('active');
  });
}

document.querySelectorAll('.nav li').forEach(li => {
  li.addEventListener('click', () => switchPage(li.dataset.page));
});

document.querySelectorAll('.card').forEach(card => {
  card.addEventListener('click', () => {
    const page = card.querySelector('.card-title')?.textContent;
  });
});

// ========== Quick Start ==========
document.getElementById('btn-quick-attack')?.addEventListener('click', () => {
  const url = document.getElementById('target-url').value.trim();
  if (!url) return alert('请输入目标 URL');
  document.getElementById('attack-target').value = url;
  switchPage('attack');
  startAttack();
});

// ========== Attack ==========
document.getElementById('btn-start-attack')?.addEventListener('click', startAttack);

async function startAttack() {
  const target = document.getElementById('attack-target').value.trim();
  if (!target) return alert('请输入目标 URL');

  // Gather selected modules
  const modules = [];
  document.querySelectorAll('.checkbox-group input[type="checkbox"]').forEach(cb => {
    if (cb.checked && cb.value) modules.push(cb.value);
  });
  const timeBased = document.getElementById('cb-timebased')?.checked || false;

  // Show progress
  const progressPanel = document.getElementById('scan-progress');
  const resultsPanel = document.getElementById('scan-results');
  progressPanel.style.display = 'block';
  resultsPanel.style.display = 'none';
  document.getElementById('progress-steps').innerHTML = '<div class="progress-step running"><div class="dot"></div> 正在授权...</div>';
  document.getElementById('results-list').innerHTML = '';

  try {
    // Authorize
    await fetch(API + '/authorize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target})
    });

    // Start attack
    const resp = await fetch(API + '/attack', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target, modules, time_based: timeBased})
    });
    const data = await resp.json();

    // Poll progress
    pollProgress();
  } catch (e) {
    document.getElementById('progress-steps').innerHTML =
      `<div class="progress-step error"><div class="dot"></div> 连接失败: ${e.message}</div>`;
  }
}

function pollProgress() {
  if (scanPollTimer) clearInterval(scanPollTimer);
  scanPollTimer = setInterval(async () => {
    try {
      const resp = await fetch(API + '/scan/progress');
      const data = await resp.json();
      renderProgress(data);
      if (data.status === 'done' || data.status === 'error') {
        clearInterval(scanPollTimer);
        renderResults(data);
      }
    } catch (e) {}
  }, 1500);
}

const MODULE_NAMES = {
  xss: 'XSS 跨站脚本', sqli: 'SQL 注入', ssti: '模板注入',
  lfi: '文件包含', infoleak: '信息泄露'
};

function renderProgress(data) {
  const container = document.getElementById('progress-steps');
  let html = '';

  // SPA detect
  const spaStep = data.progress?.find(p => p.step === 'spa_detect');
  if (spaStep) {
    html += `<div class="progress-step done"><div class="dot"></div> SPA 检测: ${spaStep.is_spa ? '是 (已启用基线过滤)' : '否'}</div>`;
  }

  // Module steps
  for (const p of (data.progress || [])) {
    if (p.step === 'spa_detect') continue;
    const name = MODULE_NAMES[p.step] || p.step;
    const status = p.status || 'running';
    const count = p.count !== undefined ? ` (${p.count} 个发现)` : '';
    html += `<div class="progress-step ${status}"><div class="dot"></div> ${name}${count}</div>`;
  }

  if (data.status === 'running' && !html.includes('running')) {
    html += '<div class="progress-step running"><div class="dot"></div> 扫描中...</div>';
  }

  container.innerHTML = html;
}

function renderResults(data) {
  const resultsPanel = document.getElementById('scan-results');
  resultsPanel.style.display = 'block';

  const findings = data.findings || [];

  // Summary badges
  const counts = {};
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  let summaryHtml = '';
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    if (counts[sev]) {
      summaryHtml += `<span class="summary-badge ${sev}">${sev}: ${counts[sev]}</span>`;
    }
  }
  if (!summaryHtml) summaryHtml = '<span class="summary-badge" style="color:var(--green)">未发现漏洞</span>';
  document.getElementById('results-summary').innerHTML = summaryHtml;

  // Finding list
  const sortOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sortOrder[a.severity]||5) - (sortOrder[b.severity]||5));

  let listHtml = '';
  findings.forEach(f => {
    listHtml += `
      <div class="finding-item ${f.severity}">
        <div class="finding-header">
          <span class="finding-title">${escHtml(f.title)}</span>
          <span class="finding-severity ${f.severity}">${f.severity.toUpperCase()}</span>
        </div>
        <div class="finding-detail">
          <div>类型: ${f.vuln_type} | 位置: <code>${escHtml(f.location?.substring(0,80))}</code></div>
          ${f.payload ? `<div>Payload: <code>${escHtml(f.payload?.substring(0,100))}</code></div>` : ''}
          ${f.evidence ? `<div>证据: ${escHtml(f.evidence?.substring(0,150))}</div>` : ''}
          ${f.remediation ? `<div>修复: ${escHtml(f.remediation?.substring(0,100))}</div>` : ''}
        </div>
      </div>`;
  });
  if (!listHtml) listHtml = '<p class="empty">未发现漏洞，目标基础防护较好</p>';
  document.getElementById('results-list').innerHTML = listHtml;

  // Save to report
  saveReport(data);
}

// ========== Arsenal ==========
async function loadArsenal() {
  try {
    const resp = await fetch(API + '/arsenal');
    const data = await resp.json();
    renderArsenal(data);
    document.getElementById('arsenal-count').innerHTML = `弹药: <span>${data.total} 条</span>`;
  } catch (e) {
    document.getElementById('arsenal-table').innerHTML = '<p class="empty">无法连接后端</p>';
  }
}

function renderArsenal(data) {
  const cats = data.categories || {};
  const maxVal = Math.max(...Object.values(cats), 1);

  let html = `<table>
    <tr><th>类别</th><th>数量</th><th>分布</th></tr>`;
  for (const [cat, count] of Object.entries(cats).sort((a,b) => b[1]-a[1])) {
    const width = Math.round((count / maxVal) * 200);
    html += `<tr>
      <td><strong>${cat}</strong></td>
      <td>${count}</td>
      <td class="bar-cell"><div class="bar" style="width:${width}px"></div></td>
    </tr>`;
  }
  html += '</table>';
  document.getElementById('arsenal-table').innerHTML = html;
}

document.getElementById('btn-learn')?.addEventListener('click', async () => {
  const btn = document.getElementById('btn-learn');
  btn.textContent = '⏳ 学习中...';
  btn.disabled = true;
  try {
    const resp = await fetch(API + '/learn', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({force: true})
    });
    const data = await resp.json();
    renderArsenal(data);
    document.getElementById('arsenal-count').innerHTML = `弹药: <span>${data.total} 条</span>`;
    btn.textContent = '✅ 学习完成！';
    setTimeout(() => { btn.textContent = '🔄 从 GitHub 学习 (全量)'; btn.disabled = false; }, 2000);
  } catch (e) {
    btn.textContent = '❌ 失败: ' + e.message;
    setTimeout(() => { btn.textContent = '🔄 从 GitHub 学习 (全量)'; btn.disabled = false; }, 3000);
  }
});

document.getElementById('btn-refresh-arsenal')?.addEventListener('click', loadArsenal);

// ========== CTF Learn ==========
document.querySelectorAll('.learn-card').forEach(card => {
  card.addEventListener('click', async () => {
    const type = card.dataset.type;
    try {
      const resp = await fetch(API + '/ctf/guide/' + type);
      const data = await resp.json();
      renderLearnDetail(data);
    } catch (e) {
      console.error(e);
    }
  });
});

function renderLearnDetail(data) {
  const panel = document.getElementById('learn-detail');
  const content = document.getElementById('learn-content');

  let html = `<h2>${data.name}</h2>
    <p style="color:var(--text2);margin-bottom:16px">${data.what}</p>

    <h4>🔍 如何发现</h4>
    <ul>${(data.how_to_find||[]).map(i => `<li>${i}</li>`).join('')}</ul>

    <h4>🏆 CTF 技巧</h4>
    <ul>${(data.ctf_tips||[]).map(i => `<li><code>${escHtml(i)}</code></li>`).join('')}</ul>

    <h4>🛠 常用工具</h4>
    <div class="tools">${(data.tools||[]).map(t => `<span class="tool-tag">${t}</span>`).join('')}</div>`;

  content.innerHTML = html;
  panel.style.display = 'block';
}

// ========== Reports ==========
const reports = [];

function saveReport(scanData) {
  reports.unshift({
    target: scanData.target,
    time: new Date().toLocaleString(),
    findings: scanData.findings?.length || 0,
    data: scanData
  });
  renderReports();
}

function renderReports() {
  const container = document.getElementById('report-list');
  if (!reports.length) {
    container.innerHTML = '<p class="empty">暂无报告</p>';
    return;
  }
  let html = '';
  reports.forEach((r, i) => {
    const counts = {};
    (r.data?.findings||[]).forEach(f => { counts[f.severity] = (counts[f.severity]||0)+1; });
    const summary = Object.entries(counts).map(([k,v]) => `${k}:${v}`).join(' ');
    html += `<div class="finding-item" style="cursor:pointer" onclick="rerenderReport(${i})">
      <div class="finding-header">
        <span class="finding-title">${escHtml(r.target)}</span>
        <span style="font-size:12px;color:var(--text2)">${r.time}</span>
      </div>
      <div class="finding-detail">发现 ${r.findings} 个漏洞 ${summary ? '| ' + summary : ''}</div>
    </div>`;
  });
  container.innerHTML = html;
}

// ========== Utils ==========
function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ========== Init ==========
loadArsenal();
