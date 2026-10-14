(function () {
  var b = document.querySelector(".theme");
  if (!b) return;
  function current() {
    var t = document.documentElement.dataset.theme;
    if (t) return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function label() { b.textContent = current() === "dark" ? "Light" : "Dark"; }
  label();
  b.addEventListener("click", function () {
    var next = current() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (e) {}
    label();
  });
})();
