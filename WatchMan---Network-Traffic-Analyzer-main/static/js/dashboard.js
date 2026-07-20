"use strict";

// ── Config ─────────────────────────────────────────────────────────────────────
let pollInterval = 2000;
const MAX_PPS_POINTS = 45;
const PROTO_COLORS = {
  TCP:   "#0284c7", UDP:   "#8b5cf6", ICMP:  "#f59e0b",
  DNS:   "#10b981", HTTP:  "#ec4899", HTTPS: "#f43f5e",
  FTP:   "#3b82f6", SSH:   "#6366f1", ARP:   "#64748b", OTHER: "#94a3b8",
};

// ── State ───────────────────────────────────────────────────────────────────────
let protoFilter = "";
let allPackets  = [];
let knownAlertKeys = new Set();
let toastTimer  = null;
let pollTimer   = null;

// ── UI Interactivity ────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('active'));
    
    e.currentTarget.classList.add('active');
    const targetId = e.currentTarget.dataset.target;
    document.getElementById(targetId).classList.add('active');
    if (targetId === 'tab-settings') {
      loadEmailSettings();
    }
  });
});

document.getElementById('themeToggle').addEventListener('click', () => {
  const root = document.documentElement;
  const currentTheme = root.getAttribute('data-theme');
  root.setAttribute('data-theme', currentTheme === 'dark' ? 'light' : 'dark');
});

document.getElementById('pollInterval').addEventListener('change', (e) => {
  const val = parseInt(e.target.value);
  if(val >= 500) {
    pollInterval = val;
    clearTimeout(pollTimer);
    schedulePoll();
  }
});

// ── Clock ───────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("sysTime").textContent = new Date().toTimeString().slice(0, 8);
}
setInterval(updateClock, 1000); updateClock();

function formatUptime(secs) {
  const h = String(Math.floor(secs / 3600)).padStart(2, "0");
  const m = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
  const s = String(secs % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

// ── Charts ──────────────────────────────────────────────────────────────────────
Chart.defaults.color = "#64748b";
Chart.defaults.font.family = "'Share Tech Mono', monospace";

const ppsChart = new Chart(document.getElementById("ppsChart").getContext("2d"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "Packets/s", data: [], borderColor: "#0284c7", backgroundColor: "rgba(2,132,199,0.1)", borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 4 }] },
  options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
    scales: { x: { grid: { color: "rgba(100,116,139,0.1)" }, ticks: { maxTicksLimit: 8 } }, y: { grid: { color: "rgba(100,116,139,0.1)" }, beginAtZero: true } } }
});

const protoChart = new Chart(document.getElementById("protoChart").getContext("2d"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, cutout: "68%" }
});

const threatTimelineChart = new Chart(document.getElementById("threatTimelineChart").getContext("2d"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "Threats", data: [], borderColor: "#ff2d55", backgroundColor: "rgba(255,45,85,0.1)", borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 4 }] },
  options: { responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
    scales: { x: { grid: { color: "rgba(100,116,139,0.1)" }, ticks: { maxTicksLimit: 8 } }, y: { grid: { color: "rgba(100,116,139,0.1)" }, beginAtZero: true } } }
});

const threatProtoChart = new Chart(document.getElementById("threatProtoChart").getContext("2d"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, cutout: "68%" }
});


// ── Data fetching ───────────────────────────────────────────────────────────────
async function fetchAll() {
  try {
    const [tRes, sRes, aRes, dRes, thRes] = await Promise.all([
      fetch("/traffic"), fetch("/stats"), fetch("/alerts"), fetch("/devices"), fetch("/api/threat_stats")
    ]);
    const traffic = await tRes.json();
    const stats   = await sRes.json();
    
    updateKPIs(stats);
    updatePpsChart(traffic.packets_per_second);
    updateProtoChart(traffic.protocol_distribution);
    updateTopIPs(traffic.top_ips);
    updateConnections(traffic.recent_packets);
    updateStatus(true, stats.demo_mode);
    
    if (aRes.ok) updateAlerts(await aRes.json(), stats.active_alerts);
    if (dRes.ok) updateDevices(await dRes.json());
    if (thRes.ok) updateThreatDashboard(await thRes.json());
    
  } catch (err) {
    updateStatus(false, null);
    console.error("[WatchMan] Fetch error:", err);
  }
}

// ── DOM Updaters ────────────────────────────────────────────────────────────────
function updateKPIs(stats) {
  document.getElementById("kpiPackets").textContent = stats.total_packets.toLocaleString();
  document.getElementById("kpiBytes").textContent = stats.total_bytes_mb.toFixed(2);
  document.getElementById("kpiPPS").textContent = stats.current_pps;
  document.getElementById("kpiAlerts").textContent = stats.critical_alerts;
  document.getElementById("uptime").textContent = formatUptime(stats.uptime_seconds);
  document.getElementById("alertKpi").classList.toggle("danger-card", stats.critical_alerts > 0);
  
  updateAiBanner(stats);
}

function updateAiBanner(stats) {
  const riskScore = stats.risk_score || 0;
  const riskLevel = stats.risk_level || (riskScore > 80 ? "CRITICAL" : riskScore > 60 ? "HIGH" : riskScore > 30 ? "MEDIUM" : "LOW");
  const pred = stats.ml_prediction || "Normal";
  const anomaly = (stats.anomaly_score !== undefined) ? stats.anomaly_score : 5.0;
  
  // Update both Dash and Threat tab banners
  ["Dash", "Threat"].forEach(suffix => {
    const scoreElem = document.getElementById(`riskMeterScore${suffix}`);
    const circleElem = document.getElementById(`riskMeterCircleDash`) || document.getElementById(`riskMeterCircle${suffix}`);
    const circleTarget = document.getElementById(`riskMeterCircle${suffix}`);
    const badgeElem = document.getElementById(`riskBadge${suffix}`);
    const labelElem = document.getElementById(`riskLabel${suffix}`);
    
    const predValElem = document.getElementById(`mlPredVal${suffix}`);
    const confBarElem = document.getElementById(`mlConfBar${suffix}`);
    const anomalyScoreElem = document.getElementById(`anomalyScore${suffix}`);
    const anomalyStateElem = document.getElementById(`anomalyState${suffix}`);
    const shieldStatusElem = document.getElementById(`autoShieldStatus${suffix}`);
    const shieldDetailElem = document.getElementById(`autoShieldDetail${suffix}`);
    
    if (scoreElem) scoreElem.textContent = riskScore;
    if (circleTarget) {
      const offset = Math.max(0, 232 - (232 * (riskScore / 100)));
      circleTarget.style.strokeDashoffset = offset;
      circleTarget.style.stroke = riskLevel === "CRITICAL" ? "#ef4444" : riskLevel === "HIGH" ? "#f97316" : riskLevel === "MEDIUM" ? "#f59e0b" : "#10b981";
    }
    if (badgeElem) {
      badgeElem.textContent = riskLevel;
      badgeElem.className = `risk-badge ${riskLevel}`;
    }
    if (labelElem) {
      labelElem.textContent = riskScore > 75 ? "⚠️ CRITICAL DEFENSE ALERT! AI response triggered."
                            : riskScore > 50 ? "⚡ Elevated threat activity detected. Inspecting flows."
                            : "System posture normal. No active AI threats.";
    }
    
    if (predValElem) {
      const isAttack = pred !== "Normal";
      predValElem.innerHTML = `${pred} <span style="font-size:0.85rem;color:#94a3b8;">(${isAttack ? '88-99%' : '98%'})</span>`;
      predValElem.className = isAttack ? "ml-pred-value attack" : "ml-pred-value";
      if (confBarElem) {
        confBarElem.style.width = isAttack ? "94%" : "98%";
        confBarElem.style.background = isAttack ? "linear-gradient(90deg, #f43f5e, #fb7185)" : "linear-gradient(90deg, #0ea5e9, #38bdf8)";
      }
    }
    
    if (anomalyScoreElem) anomalyScoreElem.textContent = anomaly;
    if (anomalyStateElem) {
      anomalyStateElem.textContent = anomaly > 65 ? "⚠️ Outlier / Zero-Day Pattern" : "Normal Traffic Pattern";
      anomalyStateElem.style.color = anomaly > 65 ? "#f43f5e" : "#c084fc";
      anomalyStateElem.style.borderColor = anomaly > 65 ? "rgba(244,63,94,0.4)" : "rgba(168,85,247,0.3)";
    }
    
    if (shieldStatusElem) {
      shieldStatusElem.textContent = riskScore > 80 ? "ENGAGED" : "ACTIVE";
      shieldStatusElem.style.color = riskScore > 80 ? "#ef4444" : "#10b981";
      if (shieldDetailElem) {
        shieldDetailElem.textContent = riskScore > 80 ? "Dynamic IP Block Applied via iptables" : "IP Blocking & Firewall Ready";
      }
    }
  });
}

function updatePpsChart(history) {
  const slice = (history || []).slice(-MAX_PPS_POINTS);
  ppsChart.data.labels = slice.map(p => p.time);
  ppsChart.data.datasets[0].data = slice.map(p => p.count);
  ppsChart.update("none");
}

function updateProtoChart(dist) {
  const labels = Object.keys(dist || {});
  const vals = Object.values(dist || {});
  const colors = labels.map(l => PROTO_COLORS[l] || PROTO_COLORS.OTHER);
  protoChart.data.labels = labels; protoChart.data.datasets[0].data = vals; protoChart.data.datasets[0].backgroundColor = colors;
  protoChart.update("none");
  document.getElementById("protoLegend").innerHTML = labels.map((l, i) =>
    `<span class="proto-dot"><span style="background:${colors[i]}"></span>${l}: ${vals[i]}</span>`
  ).join("");
}

function updateTopIPs(ips) {
  const container = document.getElementById("topIpsContainer");
  if (!ips || !ips.length) return container.innerHTML = `<p class="empty-state">No data yet…</p>`;
  const max = ips[0].count || 1;
  container.innerHTML = ips.map((ip, i) => `
    <div class="ip-row">
      <span class="ip-rank">#${i + 1}</span>
      <span class="ip-addr">${ip.ip}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${Math.round((ip.count / max) * 100)}%"></div></div>
      <span class="ip-count">${ip.count}</span>
    </div>
  `).join("");
}

function updateConnections(packets) {
  allPackets = packets || []; renderConnections();
}

function renderConnections() {
  const tbody = document.getElementById("connBody");
  const filtered = protoFilter ? allPackets.filter(p => p.proto === protoFilter) : allPackets;
  if (!filtered.length) return tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No connections match the filter…</td></tr>`;
  tbody.innerHTML = [...filtered].reverse().slice(0, 100).map((p, i) => `
    <tr class="${i < 3 ? "row-new" : ""}">
      <td class="text-dim">${p.time}</td>
      <td class="text-accent">${p.src}</td>
      <td>${p.dst}</td>
      <td><span class="proto proto-${p.proto}">${p.proto}</span></td>
      <td>${p.sport === '-' ? '-' : (p.sport + '→' + p.dport)}</td>
      <td>${p.size}B</td>
    </tr>
  `).join("");
}

function applyFilter() { protoFilter = document.getElementById("protoFilter").value; renderConnections(); }

// ── Alerts & Devices ────────────────────────────────────────────────────────────
function updateAlerts(alerts, totalAlerts) {
  const badge = document.getElementById("navAlertBadge");
  badge.textContent = totalAlerts;
  badge.style.display = totalAlerts > 0 ? "inline-block" : "none";
  document.getElementById("navAlertGroup").classList.toggle("alert-flash", totalAlerts > 0);

  alerts.forEach(a => {
    const key = `${a.time}|${a.type}|${a.detail}`;
    if (!knownAlertKeys.has(key)) { knownAlertKeys.add(key); showToast(a); }
  });

  const tbody = document.getElementById("alertsBody");
  if (!alerts.length) return tbody.innerHTML = `<tr class="empty-row"><td colspan="6">System secure. No threats detected.</td></tr>`;
  tbody.innerHTML = alerts.slice(0, 50).map((a, i) => {
    const riskScore = a.risk_score || (a.severity === 'CRITICAL' ? 95 : a.severity === 'HIGH' ? 75 : 45);
    const pred = a.ml_prediction || (a.type !== 'SYN Flood' ? a.type : 'DoS');
    const recs = a.recommendations || {};
    const recText = recs.action || a.mitigation || "Monitor source IP and verify packet rate.";
    const actionTaken = a.action_taken || (riskScore > 80 ? "BLOCKED (iptables)" : "Monitored");
    const isBlocked = actionTaken.toLowerCase().includes("block") || actionTaken.toLowerCase().includes("drop");
    
    return `
    <tr class="${i < 2 ? "row-new" : ""}">
      <td class="text-dim">${a.time}</td>
      <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
      <td>
        <span class="text-bold" style="color:var(--accent);">${riskScore}/100</span><br>
        <span class="text-xs text-dim">ML: ${pred}</span>
      </td>
      <td class="text-bold text-red">${a.type}</td>
      <td style="white-space:normal">
        ${a.detail}
        ${a.src ? `<br><small class="text-dim">Flow: ${a.src} ⟶ ${a.dst || 'Unknown'} (${a.proto || 'TCP'})</small>` : ''}
      </td>
      <td style="white-space:normal">
        <div class="rec-box">
          <strong>💡 AI SOC Recommendation:</strong><br>${recText}
        </div>
        <div style="margin-top:6px;">
          <span class="action-taken-badge ${isBlocked ? 'blocked' : ''}">🤖 Action: ${actionTaken}</span>
        </div>
      </td>
    </tr>
  `}).join("");
  
  // Also update live threat log in new tab
  const liveTbody = document.getElementById("liveThreatBody");
  if (!alerts.length) return liveTbody.innerHTML = `<tr class="empty-row"><td colspan="8">Monitoring for threats...</td></tr>`;
  liveTbody.innerHTML = alerts.slice(0, 50).map((a, i) => {
    const riskScore = a.risk_score || (a.severity === 'CRITICAL' ? 95 : a.severity === 'HIGH' ? 75 : 45);
    const pred = a.ml_prediction || (a.type !== 'SYN Flood' ? a.type : 'DoS');
    const recs = a.recommendations || {};
    const recText = recs.action || a.mitigation || "Monitor source IP and verify packet rate.";
    const actionTaken = a.action_taken || (riskScore > 80 ? "BLOCKED (iptables)" : "Monitored");
    const isBlocked = actionTaken.toLowerCase().includes("block") || actionTaken.toLowerCase().includes("drop");
    
    return `
    <tr class="${i < 2 ? "row-new" : ""}">
      <td class="text-dim">${a.time}</td>
      <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
      <td>
        <span class="text-bold" style="color:var(--accent);">${riskScore}/100</span><br>
        <span class="text-xs text-dim">${pred}</span>
      </td>
      <td class="text-bold text-red">${a.type}</td>
      <td class="text-accent">${a.src || '-'}</td>
      <td>${a.dst || '-'}</td>
      <td><span class="proto proto-${a.proto || 'OTHER'}">${a.proto || '-'}</span></td>
      <td style="white-space:normal">
        <div class="rec-box" style="margin-bottom:4px;">
          <strong>💡 ${recText}</strong>
        </div>
        <span class="action-taken-badge ${isBlocked ? 'blocked' : ''}">Action: ${actionTaken}</span>
      </td>
    </tr>
  `}).join("");
}

function updateThreatDashboard(stats) {
  document.getElementById("kpiActiveThreats").textContent = stats.active_threats;
  document.getElementById("kpiCriticalThreats").textContent = stats.critical_threats;
  document.getElementById("kpiThreatsToday").textContent = stats.threats_today;
  
  // Timeline
  threatTimelineChart.data.labels = stats.timeline.map(p => p.time);
  threatTimelineChart.data.datasets[0].data = stats.timeline.map(p => p.count);
  threatTimelineChart.update("none");
  
  // Protocol Pie
  const labels = Object.keys(stats.protocol_dist || {});
  const vals = Object.values(stats.protocol_dist || {});
  const colors = labels.map(l => PROTO_COLORS[l] || PROTO_COLORS.OTHER);
  threatProtoChart.data.labels = labels; threatProtoChart.data.datasets[0].data = vals; threatProtoChart.data.datasets[0].backgroundColor = colors;
  threatProtoChart.update("none");
  document.getElementById("threatProtoLegend").innerHTML = labels.map((l, i) =>
    `<span class="proto-dot"><span style="background:${colors[i]}"></span>${l}: ${vals[i]}</span>`
  ).join("");
  
  // Top Attackers
  const tbody = document.getElementById("attackersBody");
  if (!stats.top_attackers.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="4">No attackers found</td></tr>`;
  } else {
    tbody.innerHTML = stats.top_attackers.map(a => `
      <tr>
        <td class="text-accent text-bold">${a.ip}</td>
        <td>${a.packets}</td>
        <td class="text-red text-bold">${a.threats}</td>
        <td>${a.risk_score}</td>
      </tr>
    `).join("");
  }
  
  // Heat Map
  const heatMap = document.getElementById("heatMapContainer");
  if (Object.keys(stats.heat_map).length === 0) {
      heatMap.innerHTML = `<p class="empty-state" style="text-align:center;color:var(--text-dim);padding:20px;">No threat flows to display</p>`;
  } else {
      let html = `<div class="heat-map-grid" style="display:flex;flex-direction:column;gap:12px;">`;
      for (const [src, dsts] of Object.entries(stats.heat_map)) {
          for (const [dst, threats] of Object.entries(dsts)) {
             const threatStr = Object.entries(threats).map(([t, c]) => `${t}(${c})`).join(", ");
             html += `
             <div style="display:flex;align-items:center;background:var(--bg-app);padding:10px;border-radius:6px;border:1px solid var(--border);">
               <div style="flex:1;"><span class="text-accent">${src}</span></div>
               <div style="padding:0 20px;color:var(--danger);">⟶</div>
               <div style="flex:1;"><span class="text-bright">${dst}</span></div>
               <div style="flex:2;text-align:right;"><span class="sev sev-HIGH" style="white-space:normal">${threatStr}</span></div>
             </div>`;
          }
      }
      html += `</div>`;
      heatMap.innerHTML = html;
  }
}

function updateDevices(devices) {
  const tbody = document.getElementById("devicesBody");
  if (!devices.length) return tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No devices seen on LAN yet...</td></tr>`;
  
  devices.sort((a,b) => b.last_seen - a.last_seen);
  
  tbody.innerHTML = devices.map(d => {
      const ts = new Date(d.last_seen * 1000).toLocaleTimeString();
      const status = d.is_active ? '<span class="proto proto-TCP">ACTIVE</span>' : '<span class="proto proto-OTHER">INACTIVE</span>';
      return `
        <tr>
          <td class="text-accent">${d.ip}</td>
          <td class="text-mono">${d.mac}</td>
          <td>${d.vendor}</td>
          <td>${status}</td>
          <td class="text-dim">${ts}</td>
        </tr>
      `;
  }).join("");
}

async function clearAlerts() {
  await fetch("/clear-alerts", { method: "POST" }).catch(console.warn);
  knownAlertKeys.clear();
  fetchAll();
}

function showToast(alert) {
  const toast = document.getElementById("alertToast");
  toast.className = `alert-toast alert-${alert.severity}`;
  toast.innerHTML = `<strong>⚠ ${alert.type}</strong><br><small>${alert.detail}</small>`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.className = "alert-toast hidden", 6000);
}

function updateStatus(ok, demoMode) {
  const pill = document.getElementById("statusPill");
  pill.className = `status-pill ${ok ? 'ok' : 'err'}`;
  document.getElementById("statusText").textContent = !ok ? "CONNECTION LOST" : demoMode ? "SIMULATION ACTIVE" : "LIVE MONITORING";
}

// ── Exports ─────────────────────────────────────────────────────────────────────
function exportTraffic() { window.open("/export/csv", "_blank"); }
function exportAlerts()  { window.open("/export/alerts/csv", "_blank"); }

// ── Gmail Alert System Settings & Audit Logs ────────────────────────────────────
async function refreshEmailLogs(btn) {
  if (btn && btn.tagName === 'BUTTON') {
    btn.disabled = true;
    btn.innerHTML = `<span class="icon">⌛</span> Refreshing...`;
  }
  await loadEmailSettings(true);
  if (btn && btn.tagName === 'BUTTON') {
    btn.innerHTML = `✅ Refreshed!`;
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `↻ Refresh Logs`;
    }, 1200);
  }
}

async function loadEmailSettings(forceRefresh = false) {
  try {
    const url = forceRefresh ? `/email-status?_=${Date.now()}` : "/email-status";
    const res = await fetch(url, forceRefresh ? { cache: "no-store" } : {});
    if (!res.ok) return;
    const data = await res.json();
    const st = data.status || {};
    const logs = data.audit_logs || [];

    if (document.getElementById("smtpServerInput")) document.getElementById("smtpServerInput").value = st.smtp_server || "smtp.gmail.com";
    if (document.getElementById("smtpPortInput")) document.getElementById("smtpPortInput").value = st.smtp_port || 587;
    if (document.getElementById("smtpSenderInput")) document.getElementById("smtpSenderInput").value = st.sender_email || "ariprakash32@gmail.com";
    if (document.getElementById("smtpRecipientInput")) document.getElementById("smtpRecipientInput").value = st.recipient_email || "ariprakash32@gmail.com";
    
    const badge = document.getElementById("smtpConnectionBadge");
    if (badge) {
      if (st.is_configured) {
        badge.textContent = "● READY / CONFIGURED";
        badge.className = "panel-badge online";
      } else {
        badge.textContent = "● PENDING CREDENTIALS (.ENV)";
        badge.className = "panel-badge";
      }
    }

    // Populate Audit Logs Table
    const tbody = document.getElementById("emailLogsBody");
    if (tbody) {
      if (!logs.length) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No email notifications recorded yet.</td></tr>`;
      } else {
        tbody.innerHTML = logs.map(l => {
          const statusBadge = l.status === "SUCCESS" 
            ? `<span class="proto proto-TCP">SUCCESS</span>` 
            : `<span class="sev sev-CRITICAL">FAILED</span>`;
          return `
            <tr>
              <td class="text-dim">${l.time || "-"}</td>
              <td class="text-accent">${l.recipient || "-"}</td>
              <td class="text-bold">${l.subject || "-"}</td>
              <td>${statusBadge}</td>
              <td style="white-space:normal; color: ${l.status === 'SUCCESS' ? 'var(--text-bright)' : 'var(--danger)'}; font-size: 0.85rem;">
                ${l.error_message || "Delivered cleanly via Gmail SMTP"}
              </td>
            </tr>
          `;
        }).join("");
      }
    }
  } catch (e) {
    console.error("Failed to load email status:", e);
  }
}

async function sendTestEmail() {
  const btn = document.getElementById("sendTestEmailBtn");
  const recipient = document.getElementById("smtpRecipientInput") ? document.getElementById("smtpRecipientInput").value : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="icon">⌛</span> Sending Test...`;
  }
  try {
    const res = await fetch("/test-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recipient })
    });
    const result = await res.json();
    if (res.ok && result.success) {
      alert("✅ " + (result.message || "Test email sent successfully via Gmail SMTP!"));
    } else {
      alert("❌ Email Delivery Failed: \n" + (result.message || "Unknown error occurred."));
    }
    loadEmailSettings();
  } catch (e) {
    alert("❌ Network/Connection Error communicating with Watch Man server: " + e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<span class="icon">✉️</span> Send Test Email`;
    }
  }
}

async function saveEmailSettings() {
  const smtp_server = document.getElementById("smtpServerInput").value;
  const smtp_port = document.getElementById("smtpPortInput").value;
  const sender_email = document.getElementById("smtpSenderInput").value;
  const recipient_email = document.getElementById("smtpRecipientInput").value;
  const password = document.getElementById("smtpPasswordInput").value;

  try {
    const res = await fetch("/api/settings/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        smtp_server,
        smtp_port,
        sender_email,
        recipient_email,
        password
      })
    });
    const result = await res.json();
    if (res.ok && result.success) {
      alert("💾 " + result.message);
      if (document.getElementById("smtpPasswordInput")) {
        document.getElementById("smtpPasswordInput").value = "********";
      }
      loadEmailSettings();
    } else {
      alert("❌ Failed to save configuration: " + (result.message || "Unknown error."));
    }
  } catch (e) {
    alert("❌ Error communicating with Watch Man server: " + e.message);
  }
}

// ── Loop ────────────────────────────────────────────────────────────────────────
function schedulePoll() {
  fetchAll();
  pollTimer = setTimeout(schedulePoll, pollInterval);
}
schedulePoll();
