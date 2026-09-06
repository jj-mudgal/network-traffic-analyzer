// dashboard.js
// Fetches packet metadata and protocol stats from the Flask API
// and renders them into the dashboard table / stat cards.

const REFRESH_INTERVAL_MS = 5000;

async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const stats = await res.json();
    document.getElementById("stat-total").textContent = stats.total ?? 0;
    document.getElementById("stat-tcp").textContent = stats.TCP ?? 0;
    document.getElementById("stat-udp").textContent = stats.UDP ?? 0;
    document.getElementById("stat-icmp").textContent = stats.ICMP ?? 0;
  } catch (err) {
    console.error("Failed to load stats:", err);
  }
}

async function loadPackets() {
  const tbody = document.getElementById("packet-table-body");
  try {
    const res = await fetch("/api/packets");
    const packets = await res.json();

    if (!packets.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-row">No packets captured yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = packets.map(rowHtml).join("");
  } catch (err) {
    console.error("Failed to load packets:", err);
    tbody.innerHTML = `<tr><td colspan="9" class="empty-row">Could not load packets from the server.</td></tr>`;
  }
}

function rowHtml(packet) {
  const protocol = (packet.protocol || "").toUpperCase();
  return `
    <tr>
      <td>${packet.id}</td>
      <td>${escapeHtml(packet.timestamp)}</td>
      <td>${escapeHtml(packet.source_ip)}</td>
      <td>${escapeHtml(packet.destination_ip)}</td>
      <td>${packet.source_port ?? "–"}</td>
      <td>${packet.destination_port ?? "–"}</td>
      <td><span class="protocol-badge ${protocol}">${protocol}</span></td>
      <td>${packet.packet_size ?? "–"}</td>
      <td>${escapeHtml(packet.tcp_flags ?? "–")}</td>
    </tr>
  `;
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "–";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function refreshAll() {
  loadStats();
  loadPackets();
}

document.addEventListener("DOMContentLoaded", () => {
  refreshAll();
  setInterval(refreshAll, REFRESH_INTERVAL_MS);
});
