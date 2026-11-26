// Live host charts: uPlot fed by /api/v1/hosts/{id}/series and an SSE stream.
(function () {
  var COLORS = ["#0d9488", "#f59e0b", "#6366f1", "#ef4444", "#0ea5e9", "#a855f7", "#84cc16", "#ec4899"];
  var RANGES = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000 };
  var range = "1h";
  var charts = [];

  function fmt(unit, v) {
    if (v == null || isNaN(v)) return "–";
    if (unit === "%") return v.toFixed(1) + "%";
    if (unit === "B/s") {
      var u = ["B/s", "KB/s", "MB/s", "GB/s"], i = 0;
      while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
      return v.toFixed(v < 10 ? 1 : 0) + " " + u[i];
    }
    return v.toFixed(2);
  }

  function seriesLabel(key, all) {
    var m = key.match(/^([a-z0-9_]+)\.([a-z0-9_]+)(?:\{(.*)\})?$/);
    if (!m) return key;
    var metric = m[2], labels = m[3];
    if (!labels) return metric;
    var vals = labels.split(",").map(function (kv) { return kv.split("=")[1]; }).join(" ");
    var metrics = {};
    all.forEach(function (s) { metrics[s.key.split("{")[0]] = 1; });
    return Object.keys(metrics).length > 1 ? vals + " " + metric.replace(/_bps$/, "") : vals;
  }
  function axisColor() { return document.documentElement.classList.contains("dark") ? "#a1a1aa" : "#71717a"; }
  function gridColor() { return document.documentElement.classList.contains("dark") ? "#27272a" : "#f4f4f5"; }

  function build(el, data) {
    var unit = el.dataset.unit;
    var series = [{}];
    data.series.forEach(function (s, i) {
      series.push({ label: seriesLabel(s.key, data.series),  stroke: COLORS[i % COLORS.length], width: 1.5,
        fill: data.series.length === 1 ? COLORS[0] + "22" : undefined, value: function (u, v) { return fmt(unit, v); } });
    });
    var opts = {
      width: el.clientWidth, height: el.clientHeight || 192, series: series,
      scales: { x: { time: true }, y: unit === "%" ? { range: [0, 100] } : { auto: true } },
      axes: [
        { stroke: axisColor, grid: { stroke: gridColor, width: 1 }, ticks: { show: false } },
        { stroke: axisColor, grid: { stroke: gridColor, width: 1 }, ticks: { show: false }, size: 60, values: function (u, vals) { return vals.map(function (v) { return fmt(unit, v); }); } },
      ],
      legend: { live: true }, cursor: { points: { size: 5 } },
    };
    var aligned = [data.timestamps].concat(data.series.map(function (s) { return s.values; }));
    el.innerHTML = "";
    var u = new uPlot(opts, aligned, el);
    var keys = data.series.map(function (s) { return s.key; });
    var chart = { el: el, u: u, keys: keys, data: aligned, unit: unit };
    updateCurrent(chart);
    return chart;
  }

  function updateCurrent(c) {
    var cur = document.querySelector('[data-current="' + c.el.dataset.chart + '"]');
    if (!cur || c.data[0].length === 0) return;
    var last = c.data.length > 1 ? c.data[1][c.data[1].length - 1] : null;
    cur.textContent = fmt(c.unit, last);
  }

  function load(host) {
    charts.forEach(function (c) { c.u.destroy(); });
    charts = [];
    document.querySelectorAll("[data-chart]").forEach(function (el) {
      var q = "metrics=" + encodeURIComponent(el.dataset.metrics) + "&labels=" + (el.dataset.labels === "true" ? "all" : "none") + "&range=" + RANGES[range];
      fetch("/api/v1/hosts/" + host + "/series?" + q, { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (!d.series || d.series.length === 0) { el.innerHTML = '<div class="flex h-full items-center justify-center text-sm text-zinc-400">No data yet</div>'; return; }
          charts.push(build(el, d));
        });
    });
  }

  function onSamples(samples) {
    if (range !== "1h" && range !== "6h") return; // live append only for raw ranges
    charts.forEach(function (c) {
      var byTs = {};
      samples.forEach(function (s) {
        var key = s.l ? s.n + "{" + s.l + "}" : s.n;
        var idx = c.keys.indexOf(key);
        if (idx < 0) return;
        (byTs[s.t] = byTs[s.t] || {})[idx] = s.v;
      });
      var ts = Object.keys(byTs).map(Number).sort();
      var lastTs = c.data[0].length ? c.data[0][c.data[0].length - 1] : 0;
      ts.forEach(function (t) {
        if (t <= lastTs) return;
        c.data[0].push(t);
        for (var i = 0; i < c.keys.length; i++) c.data[i + 1].push(byTs[t][i] != null ? byTs[t][i] : null);
      });
      if (ts.length) {
        var cutoff = Date.now() / 1000 - RANGES[range];
        while (c.data[0].length && c.data[0][0] < cutoff) c.data.forEach(function (a) { a.shift(); });
        c.u.setData(c.data);
        updateCurrent(c);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var root = document.getElementById("charts");
    if (!root || typeof uPlot === "undefined") return;
    var host = root.dataset.host;
    load(host);
    document.querySelectorAll("#range-picker [data-range]").forEach(function (b) {
      b.addEventListener("click", function () {
        range = b.dataset.range;
        document.querySelectorAll("#range-picker [data-range]").forEach(function (x) {
          var on = x === b;
          x.className = "rounded px-2.5 py-1 font-medium " + (on ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900" : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800");
        });
        load(host);
      });
    });
    var es = new EventSource("/hosts/" + host + "/stream");
    var dot = document.getElementById("live-dot");
    es.addEventListener("metrics", function (e) { onSamples(JSON.parse(e.data)); });
    es.onerror = function () { if (dot) dot.className = "dot dot-warn"; };
    es.onopen = function () { if (dot) dot.className = "dot dot-ok animate-pulse"; };
    window.addEventListener("resize", function () { charts.forEach(function (c) { c.u.setSize({ width: c.el.clientWidth, height: c.el.clientHeight || 192 }); }); });
    document.addEventListener("sentrix:theme", function () { load(host); });
  });
})();
