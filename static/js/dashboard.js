// dashboard.js
// Fetches packet metadata and protocol stats from the Flask API
// and renders them into the dashboard table / stat cards.
// No frameworks — keeps things simple per the project's tech stack (Section 4).

const REFRESH_INTERVAL_MS = 5000;
let isRefreshing = false;

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
      <td>${formatSize(packet.packet_size)}</td>
      <td>${escapeHtml(packet.tcp_flags ?? "–")}</td>
    </tr>
  `;
}

function formatSize(bytes) {
  if (bytes === null || bytes === undefined) return "–";
  return Number(bytes).toLocaleString();
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "–";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function refreshAll() {
  if (isRefreshing) return;
  isRefreshing = true;
  try {
    await Promise.all([loadStats(), loadPackets()]);
  } finally {
    isRefreshing = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshAll();
  setInterval(refreshAll, REFRESH_INTERVAL_MS);
});