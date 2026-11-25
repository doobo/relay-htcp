// Applied before first paint so the page never flashes the wrong palette.
// Keep the storage key in sync with app.js.
(function () {
  try {
    var choice = localStorage.getItem("relay-htcp.theme") || "auto";
    var theme = choice === "auto"
      ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
      : choice;
    var root = document.documentElement;
    root.setAttribute("data-theme", theme);
    root.setAttribute("data-theme-choice", choice);
    root.style.colorScheme = theme === "light" ? "light" : "dark";
    if (sessionStorage.getItem("rhtcp_token")) {
      root.classList.add("has-auth");
    }
  } catch (e) { /* storage unavailable: keep the dark palette */ }
})();
