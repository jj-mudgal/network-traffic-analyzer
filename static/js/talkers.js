// talkers.js — "Top Source IPs" bar chart, fed by dashboard.js's stats:loaded event.
(function () {
  let chart = null;

  document.addEventListener("stats:loaded", (event) => {
    const canvas = document.getElementById("talkers-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const top = event.detail.top_source_ips || [];
    const data = {
      labels: top.map((r) => r.ip),
      datasets: [{ label: "Packets", data: top.map((r) => r.packets), backgroundColor: "#4f8cff", borderWidth: 0 }],
    };

    if (chart) {
      chart.data = data;
      chart.update();
      return;
    }
    chart = new Chart(canvas, {
      type: "bar",
      data,
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8b93a7", precision: 0 }, grid: { color: "#263047" } },
          y: { ticks: { color: "#e6e9f0" }, grid: { display: false } },
        },
      },
    });
  });
})();
