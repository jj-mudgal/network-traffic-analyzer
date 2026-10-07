// dashboard.js
// Fetches filtered packets + stats from the Flask API and renders the dashboard.

const REFRESH_INTERVAL_MS = 5000;

// One place for filter state so /api/packets and /api/stats always get
// the same query string.
const filters = {
  protocol: "",
  source_ip: "",
  destination_ip: "",
  source_port: "",
  destination_port: "",
};

let protocolChart = null;
let paused = false;
let packetsRequest = 0; // ids used to drop stale responses
let statsRequest = 0;

function buildQueryString() {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== "" && value !== null && value !== undefined) {
      params.set(key, value);
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

async function fetchJson(path) {
  const res = await fetch(`${path}${buildQueryString()}`);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || `Server returned ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return body;
}

function showFilterError(message) {
  const el = document.getElementById("filter-error");
  if (!el) return;
  el.textContent = message || "";
  el.hidden = !message;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

async function loadStats() {
  const requestId = ++statsRequest;
  try {
    const stats = await fetchJson("/api/stats");
    if (requestId !== statsRequest) return;
    setText("stat-total", stats.total_packets ?? 0);
    setText("stat-tcp", stats.tcp ?? 0);
    setText("stat-udp", stats.udp ?? 0);
    setText("stat-icmp", stats.icmp ?? 0);
    updateChart(stats);
    document.dispatchEvent(new CustomEvent("stats:loaded", { detail: stats }));
  } catch (err) {
    console.error("Failed to load stats:", err);
  }
}

async function loadPackets() {
  const requestId = ++packetsRequest;
  const tbody = document.getElementById("packet-table-body");
  try {
    const { packets } = await fetchJson("/api/packets");
    if (requestId !== packetsRequest) return;
    showFilterError("");

    if (!packets.length) {
      const hasActiveFilter = Object.values(filters).some((v) => v !== "");
      const message = hasActiveFilter
        ? "No packets match the current filters."
        : "No packets captured yet.";
      tbody.innerHTML = `<tr><td colspan="9" class="empty-row">${message}</td></tr>`;
      return;
    }
    tbody.innerHTML = packets.map(rowHtml).join("");
  } catch (err) {
    if (requestId !== packetsRequest) return;
    if (err.status === 400) {
      showFilterError(err.message);
      tbody.innerHTML = `<tr><td colspan="9" class="empty-row">Fix the invalid filter to see packets.</td></tr>`;
      return;
    }
    console.error("Failed to load packets:", err);
    tbody.innerHTML = `<tr><td colspan="9" class="empty-row">Could not load packets from the server.</td></tr>`;
  }
}

// Doughnut chart of the protocol breakdown (respects current filters).
function updateChart(stats) {
  const canvas = document.getElementById("protocol-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const data = {
    labels: ["TCP", "UDP", "ICMP", "Other"],
    datasets: [
      {
        data: [stats.tcp ?? 0, stats.udp ?? 0, stats.icmp ?? 0, stats.other ?? 0],
        backgroundColor: ["#4f8cff", "#34c98f", "#f2a541", "#5b6478"],
        borderWidth: 0,
      },
    ],
  };

  if (protocolChart) {
    protocolChart.data = data;
    protocolChart.update();
    return;
  }

  protocolChart = new Chart(canvas, {
    type: "doughnut",
    data,
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom", labels: { color: "#e6e9f0" } } },
    },
  });
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
      <td><span class="protocol-badge ${escapeHtml(protocol)}">${escapeHtml(protocol)}</span></td>
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
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function refreshAll() {
  loadStats();
  loadPackets();
}

function debounce(fn, delayMs) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delayMs);
  };
}

const debouncedRefresh = debounce(refreshAll, 400);

function setupFilterControls() {
  const protocolButtons = document.querySelectorAll(".protocol-filter-btn");
  protocolButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      protocolButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      filters.protocol = btn.dataset.protocol;
      refreshAll();
    });
  });

  const inputMap = {
    "filter-source-ip": "source_ip",
    "filter-destination-ip": "destination_ip",
    "filter-source-port": "source_port",
    "filter-destination-port": "destination_port",
  };
  for (const [id, filterKey] of Object.entries(inputMap)) {
    const el = document.getElementById(id);
    el.addEventListener("input", () => {
      filters[filterKey] = el.value.trim();
      debouncedRefresh();
    });
  }

  document.getElementById("clear-filters").addEventListener("click", () => {
    for (const key of Object.keys(filters)) filters[key] = "";
    protocolButtons.forEach((b) => b.classList.remove("active"));
    document.querySelector('.protocol-filter-btn[data-protocol=""]').classList.add("active");
    for (const id of Object.keys(inputMap)) document.getElementById(id).value = "";
    refreshAll();
  });
}

// Small hook for the other dashboard scripts (capture.js, alerts.js).
window.dashboard = {
  refresh: refreshAll,
  setPaused(value) { paused = value; },
  isPaused() { return paused; },
};

document.addEventListener("DOMContentLoaded", () => {
  setupFilterControls();
  refreshAll();
  setInterval(() => { if (!paused) refreshAll(); }, REFRESH_INTERVAL_MS);
});
