// Light / dark theme. The choice is kept in this browser; with no choice the
// page follows the system setting. Loaded in <head> so the theme is applied
// before the page paints.
(function () {
  "use strict";
  var KEY = "lolbins-theme";
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function stored() {
    try { var v = window.localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : null; } catch (e) { return null; }
  }
  function current() { return stored() || (media && media.matches ? "dark" : "light"); }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    var meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute("content", theme);
  }

  apply(current());

  var SUN = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6"/></svg>';
  var MOON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>';

  function icon(markup) {
    var doc = new DOMParser().parseFromString(markup, "image/svg+xml");
    return document.importNode(doc.documentElement, true);
  }

  function paint(btn) {
    var dark = root.getAttribute("data-theme") === "dark";
    btn.textContent = "";
    btn.appendChild(icon(dark ? SUN : MOON));
    btn.appendChild(document.createTextNode(dark ? "Light mode" : "Dark mode"));
    btn.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    btn.setAttribute("aria-pressed", dark ? "true" : "false");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    paint(btn);
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      apply(next);
      try { window.localStorage.setItem(KEY, next); } catch (e) { /* private mode: the choice lasts for this visit */ }
      paint(btn);
      document.dispatchEvent(new CustomEvent("themechange", { detail: next }));
    });
    // With no saved choice, follow the system when it changes.
    if (media && media.addEventListener) {
      media.addEventListener("change", function () {
        if (stored()) return;
        apply(current());
        paint(btn);
        document.dispatchEvent(new CustomEvent("themechange", { detail: current() }));
      });
    }
  });
})();
