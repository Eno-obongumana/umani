let selectedModules = new Set();

async function loadModules() {
  const r = await fetch('/api/modules');
  const mods = await r.json();
  const ul = document.getElementById('modules');
  ul.innerHTML = '';
  mods.forEach(m => {
    const li = document.createElement('li');
    li.innerHTML = `
      <label style="display:flex;align-items:center;gap:8px;width:100%;cursor:pointer;">
        <input type="checkbox" value="${m.name}" onchange="toggleModule(this)">
        <span style="flex:1;">${m.name}</span>
        <span class="badge ${m.severity}">${m.severity}</span>
      </label>`;
    ul.appendChild(li);
  });
}

function toggleModule(cb) {
  if (cb.checked) selectedModules.add(cb.value);
  else selectedModules.delete(cb.value);
}

function selectAll() {
  document.querySelectorAll('#modules input[type=checkbox]').forEach(cb => {
    cb.checked = true; selectedModules.add(cb.value);
  });
}

function selectNone() {
  document.querySelectorAll('#modules input[type=checkbox]').forEach(cb => {
    cb.checked = false;
  });
  selectedModules.clear();
}

async function loadScans() {
  const r = await fetch('/api/scans');
  const scans = await r.json();
  const el = document.getElementById('scans');
  if (!scans.length) {
    el.innerHTML = '<div style="color:#52525b;font-size:0.8rem;">No scans yet</div>';
    return;
  }
  el.innerHTML = scans.slice(0, 20).map(s =>
    `<div class="scan-item" onclick="viewScan(${s.id})">
       #${s.id} — ${s.target.slice(0, 40)}
       <small>${s.finding_count} finding${s.finding_count === 1 ? '' : 's'}</small>
     </div>`).join('');
}

async function viewScan(id) {
  const r = await fetch(`/api/scans/${id}`);
  const findings = await r.json();
  renderFindings(findings, id);
}

function renderFindings(findings, scanId) {
  const el = document.getElementById('results');
  const reportLink = scanId
    ? `<button class="secondary" onclick="window.open('/report/${scanId}','_blank')">View Report</button>`
    : '';
  if (!findings.length) {
    el.innerHTML = `<div class="empty">No findings ${scanId ? 'for scan #'+scanId : ''}. ${reportLink}</div>`;
    return;
  }
  const rows = findings.map(f => `
    <tr>
      <td><span class="badge ${f.severity}">${f.severity}</span></td>
      <td>${f.module}</td>
      <td>${escapeHtml(f.name)}</td>
      <td style="color:#71717a;word-break:break-all;">${escapeHtml(f.url || '')}</td>
    </tr>`).join('');
  el.innerHTML = `
    <div style="margin-bottom:1rem;display:flex;gap:1rem;align-items:center;">
      <div>${findings.length} finding${findings.length === 1 ? '' : 's'}</div>
      ${reportLink}
    </div>
    <table class="findings">
      <thead>
        <tr><th>Severity</th><th>Module</th><th>Finding</th><th>URL</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

async function runScan() {
  const target = document.getElementById('target').value.trim();
  const cookie = document.getElementById('cookie').value.trim();
  if (!target) return;

  const btn = document.getElementById('scan-btn');
  const status = document.getElementById('status');
  btn.disabled = true;
  status.innerHTML = '<span class="spinner"></span>Scanning…';

  try {
    const payload = { target };
    if (cookie) payload.cookie = cookie;
    if (selectedModules.size) payload.modules = Array.from(selectedModules);
    const r = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || 'Scan failed');
    renderFindings(data.findings, data.scan_id);
    loadScans();
    status.textContent = `Scan #${data.scan_id} complete`;
  } catch (e) {
    status.textContent = 'Error: ' + e.message;
    document.getElementById('results').innerHTML =
      `<div class="empty" style="color:#b91c1c;">${escapeHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

loadModules();
loadScans();
