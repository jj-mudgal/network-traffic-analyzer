// dashboard.js
// Fetches packet metadata and protocol stats from the Flask API
// and renders them into the dashboard table / stat cards.

const REFRESH_INTERVAL_MS = 5000;

// Current filter state. Kept in one place so building the query string
// for both /api/packets and /api/stats always stays in sync.
const filters = {
  protocol: "",
  source_ip: "",
  destination_ip: "",
  source_port: "",
  destination_port: "",
};

let protocolChart = null;

// Builds a query string like "?protocol=TCP&source_ip=192.168" from the
// current filter state, skipping any filter that's empty.
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

async function loadStats() {
  try {
    const res = await fetch(`/api/stats${buildQueryString()}`);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const stats = await res.json();
    document.getElementById("stat-total").textContent = stats.total ?? 0;
    document.getElementById("stat-tcp").textContent = stats.TCP ?? 0;
    document.getElementById("stat-udp").textContent = stats.UDP ?? 0;
    document.getElementById("stat-icmp").textContent = stats.ICMP ?? 0;
    updateChart(stats);
  } catch (err) {
    console.error("Failed to load stats:", err);
  }
}

async function loadPackets() {
  const tbody = document.getElementById("packet-table-body");
  try {
    const res = await fetch(`/api/packets${buildQueryString()}`);
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    const packets = await res.json();

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
    console.error("Failed to load packets:", err);
    tbody.innerHTML = `<tr><td colspan="9" class="empty-row">Could not load packets from the server.</td></tr>`;
  }
}

// Renders/updates the Chart.js doughnut chart showing protocol breakdown.
function updateChart(stats) {
  const canvas = document.getElementById("protocol-chart");
  if (!canvas || typeof Chart === "undefined") return; // Chart.js failed to load — chart just won't render

  const data = {
    labels: ["TCP", "UDP", "ICMP", "Other"],
    datasets: [
      {
        data: [stats.TCP ?? 0, stats.UDP ?? 0, stats.ICMP ?? 0, stats.OTHER ?? 0],
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
      plugins: {
        legend: { position: "bottom", labels: { color: "#e6e9f0" } },
      },
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
    filters.protocol = "";
    filters.source_ip = "";
    filters.destination_ip = "";
    filters.source_port = "";
    filters.destination_port = "";

    protocolButtons.forEach((b) => b.classList.remove("active"));
    document.querySelector('.protocol-filter-btn[data-protocol=""]').classList.add("active");
    for (const id of Object.keys(inputMap)) {
      document.getElementById(id).value = "";
    }

    refreshAll();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setupFilterControls();
  refreshAll();
  setInterval(refreshAll, REFRESH_INTERVAL_MS);
});
