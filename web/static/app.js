// Sentrix UI helpers: theme toggle, copy buttons, relative times.
(function () {
  // Localized strings come from data-t-* attributes on <body> (see layout.html).
  function tr(name, fallback) { var v = document.body && document.body.dataset[name]; return v || fallback; }
  function fmt(f, v) { return f.replace(/%[sd]/, v); }
  function relTime(sec) {
    var d = Math.round(Date.now() / 1000 - sec);
    var future = d < 0; d = Math.abs(d);
    var u = tr("tUnits", "%ds|%dm|%dh|%dd").split("|");
    var s = d < 60 ? fmt(u[0], d) : d < 3600 ? fmt(u[1], Math.floor(d / 60)) : d < 86400 ? fmt(u[2], Math.floor(d / 3600)) : fmt(u[3], Math.floor(d / 86400));
    return fmt(future ? tr("tIn", "in %s") : tr("tAgo", "%s ago"), s);
  }
  function init(root) {
    root.querySelectorAll("[data-reltime]").forEach(function (el) { el.textContent = relTime(+el.dataset.reltime); });
    root.querySelectorAll("pre[data-copy]").forEach(function (el) {
      if (el.dataset.bound) return; el.dataset.bound = "1";
      el.title = tr("tCopy", "Click to copy"); el.style.cursor = "copy";
      el.addEventListener("click", function () {
        navigator.clipboard.writeText(el.textContent.trim());
        el.classList.add("ring-2", "ring-teal-500"); setTimeout(function () { el.classList.remove("ring-2", "ring-teal-500"); }, 600);
      });
    });
  }
  document.addEventListener("DOMContentLoaded", function () {
    init(document);
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", function () {
        var dark = document.documentElement.classList.toggle("dark");
        localStorage.setItem("sentrix-theme", dark ? "dark" : "light");
        document.dispatchEvent(new Event("sentrix:theme"));
      });
    });
    setInterval(function () { init(document); }, 30000);
    document.querySelectorAll("[data-sidebar-toggle]").forEach(function (b) {
      b.addEventListener("click", function () { var s = document.getElementById("sidebar"); s.classList.toggle("hidden"); s.classList.toggle("flex"); });
    });
    document.addEventListener("change", function (e) { if (e.target.matches("[data-autosubmit]")) e.target.form.submit(); });
    document.addEventListener("submit", function (e) {
      var msg = e.target.getAttribute("data-confirm");
      if (msg && !window.confirm(msg)) e.preventDefault();
    }, true);
  });
  document.addEventListener("htmx:afterSwap", function (e) { init(e.target); });
})();
