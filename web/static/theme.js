// Applied synchronously in <head> to avoid a flash of the wrong theme.
(function () {
  var t = localStorage.getItem("sentrix-theme");
  if (t === "dark" || (!t && window.matchMedia("(prefers-color-scheme: dark)").matches)) {
    document.documentElement.classList.add("dark");
  }
})();
