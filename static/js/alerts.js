// alerts.js — renders /api/alerts into the Security Alerts panel.
(function () {
  const body = document.getElementById("alerts-table-body");

  async function loadAlerts() {
    try {
      const res = await fetch("/api/alerts?limit=50");
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const { alerts } = await res.json();

      if (!alerts.length) {
        body.innerHTML = '<tr><td colspan="5" class="empty-row">No alerts raised by the current rules.</td></tr>';
        return;
      }
      body.innerHTML = alerts.map((a) => `
        <tr>
          <td>${escapeHtml(a.timestamp)}</td>
          <td><span class="severity-badge ${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
          <td>${escapeHtml(a.alert_type)}</td>
          <td>${escapeHtml(a.source_ip)}</td>
          <td class="desc">${escapeHtml(a.description)}</td>
        </tr>`).join("");
    } catch (err) {
      console.error("Failed to load alerts:", err);
      body.innerHTML = '<tr><td colspan="5" class="empty-row">Could not load alerts from the server.</td></tr>';
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadAlerts();
    setInterval(() => { if (!window.dashboard.isPaused()) loadAlerts(); }, 5000);
  });
})();
