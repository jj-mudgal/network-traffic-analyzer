// capture.js — capture start/stop controls and the auto-refresh toggle.
(function () {
  const select = document.getElementById("capture-interface");
  const startBtn = document.getElementById("capture-start");
  const stopBtn = document.getElementById("capture-stop");
  const pill = document.getElementById("capture-status");
  const message = document.getElementById("capture-message");
  const toggle = document.getElementById("refresh-toggle");

  async function api(path, options) {
    const res = await fetch(path, options);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Server returned ${res.status}`);
    return body;
  }

  function showMessage(text, isError) {
    message.textContent = text || "";
    message.hidden = !text;
    message.classList.toggle("error", !!isError);
  }

  function render(status) {
    const state = status.error ? "error" : status.running ? "running" : "idle";
    pill.className = `status-pill status-${state}`;
    pill.textContent = status.error
      ? "Error"
      : status.running
        ? `Capturing on ${status.interface} (${status.packets_stored} stored)`
        : "Idle";
    startBtn.disabled = status.running;
    stopBtn.disabled = !status.running;
    if (status.error) {
      showMessage(`${status.error}. Live capture needs root (run with sudo).`, true);
    }
  }

  async function loadInterfaces() {
    try {
      const { interfaces } = await api("/api/capture/interfaces");
      select.innerHTML = interfaces.map((n) => `<option>${escapeHtml(n)}</option>`).join("");
      const preferred = ["en0", "eth0"].find((n) => interfaces.includes(n));
      if (preferred) select.value = preferred;
    } catch (err) {
      select.innerHTML = '<option value="">unavailable</option>';
    }
  }

  async function refreshStatus() {
    try { render(await api("/api/capture/status")); } catch (err) { console.error(err); }
  }

  startBtn.addEventListener("click", async () => {
    showMessage("");
    try {
      render(await api("/api/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: select.value }),
      }));
    } catch (err) {
      showMessage(err.message, true);
    }
  });

  stopBtn.addEventListener("click", async () => {
    showMessage("");
    try { render(await api("/api/capture/stop", { method: "POST" })); }
    catch (err) { showMessage(err.message, true); }
  });

  toggle.addEventListener("click", () => {
    const paused = !window.dashboard.isPaused();
    window.dashboard.setPaused(paused);
    toggle.textContent = paused ? "Resume auto-refresh" : "Pause auto-refresh";
    if (!paused) window.dashboard.refresh();
  });

  document.addEventListener("DOMContentLoaded", () => {
    loadInterfaces();
    refreshStatus();
    setInterval(refreshStatus, 3000);
  });
})();
