// JSON graph view: lays a JSON document out left to right the way JSON Crack
// does. Objects are boxes listing their simple fields; every nested field gets
// a key node ("paths [2]") whose children are the nested values. Drag to pan,
// scroll or pinch to zoom, click a key node to fold or unfold it.
var JsonGraph = (function () {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";
  var FONT = "12px 'IBM Plex Mono', Consolas, Menlo, monospace";
  var ROW = 20, PAD_X = 10, PAD_Y = 7, MAX_W = 380, COL_GAP = 70, ROW_GAP = 14;
  var measureCtx = document.createElement("canvas").getContext("2d");

  function textWidth(s) {
    measureCtx.font = FONT;
    return measureCtx.measureText(s).width;
  }

  function isPrimitive(v) { return v === null || typeof v !== "object"; }

  function fmt(v) { return typeof v === "string" ? "\"" + v + "\"" : String(v); }

  function kind(v) { return v === null ? "null" : typeof v; }

  var nextId = 0;

  // Build the node tree for a value.
  function objectNode(obj) {
    var rows = [], kids = [];
    Object.keys(obj).forEach(function (k) {
      var v = obj[k];
      if (isPrimitive(v)) rows.push({ key: k, value: v });
      else kids.push(keyNode(k, v));
    });
    return { id: nextId++, type: "object", rows: rows, children: kids };
  }

  function keyNode(label, v) {
    var count = Array.isArray(v) ? "[" + v.length + "]" : "{" + Object.keys(v).length + "}";
    return { id: nextId++, type: "key", label: label, count: count, children: expand(v), collapsed: false };
  }

  function expand(v) {
    if (Array.isArray(v)) {
      return v.map(function (item, i) {
        if (isPrimitive(item)) return { id: nextId++, type: "value", value: item, children: [] };
        if (Array.isArray(item)) return keyNode("[" + i + "]", item);
        return objectNode(item);
      });
    }
    return [objectNode(v)];
  }

  function clip(s, maxW) {
    if (textWidth(s) <= maxW) return s;
    var lo = 0, hi = s.length;
    while (lo < hi) {
      var mid = (lo + hi + 1) >> 1;
      if (textWidth(s.slice(0, mid) + "…") <= maxW) lo = mid; else hi = mid - 1;
    }
    return s.slice(0, lo) + "…";
  }

  // Size every node from its text.
  function measure(n) {
    if (n.type === "object") {
      var w = 40;
      n.lines = n.rows.map(function (r) {
        var keyText = r.key + ": ";
        var full = fmt(r.value);
        var shown = clip(full, MAX_W - 2 * PAD_X - textWidth(keyText));
        w = Math.max(w, textWidth(keyText + shown) + 2 * PAD_X);
        return { key: keyText, value: shown, full: full, kind: kind(r.value) };
      });
      if (!n.lines.length) { n.lines = [{ key: "", value: "{ }", full: "{ }", kind: "null" }]; }
      n.w = Math.min(MAX_W, Math.ceil(w));
      n.h = n.lines.length * ROW + 2 * PAD_Y;
    } else if (n.type === "key") {
      n.w = Math.ceil(textWidth(n.label + " " + n.count) + 2 * PAD_X + 14);
      n.h = ROW + 2 * PAD_Y;
    } else {
      var full = fmt(n.value);
      n.shown = clip(full, MAX_W - 2 * PAD_X);
      n.full = full;
      n.w = Math.ceil(Math.max(40, textWidth(n.shown) + 2 * PAD_X));
      n.h = ROW + 2 * PAD_Y;
    }
    n.children.forEach(measure);
  }

  function visibleChildren(n) { return n.collapsed ? [] : n.children; }

  // Left-to-right tidy layout: columns by depth, leaves stacked, parents centred.
  function layout(root) {
    var colW = [];
    (function widths(n, d) {
      colW[d] = Math.max(colW[d] || 0, n.w);
      visibleChildren(n).forEach(function (c) { widths(c, d + 1); });
    })(root, 0);
    var colX = [0];
    for (var i = 1; i < colW.length; i++) colX[i] = colX[i - 1] + colW[i - 1] + COL_GAP;

    function shift(n, dy) {
      n.y += dy;
      visibleChildren(n).forEach(function (c) { shift(c, dy); });
    }
    function place(n, d, y) {
      n.x = colX[d];
      var kids = visibleChildren(n);
      if (!kids.length) { n.y = y; return y + n.h + ROW_GAP; }
      var next = y;
      kids.forEach(function (c) { next = place(c, d + 1, next); });
      var first = kids[0], last = kids[kids.length - 1];
      n.y = (first.y + last.y + last.h) / 2 - n.h / 2;
      if (n.y < y) { var dy = y - n.y; kids.forEach(function (c) { shift(c, dy); }); n.y = y; next += dy; }
      return Math.max(next, n.y + n.h + ROW_GAP);
    }
    var bottom = place(root, 0, 0);
    return { width: colX[colX.length - 1] + colW[colW.length - 1], height: bottom };
  }

  function svg(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

  function mount(container, data, opts) {
    nextId = 0;
    var root = objectNode(data);
    measure(root);
    // Big branches start folded so the first view shows the file's outline.
    function descendants(n) { return n.children.reduce(function (t, c) { return t + 1 + descendants(c); }, 0); }
    var foldOver = (opts && opts.foldOver) || 12;
    (function fold(n) {
      if (n.type === "key" && descendants(n) > foldOver) n.collapsed = true;
      n.children.forEach(fold);
    })(root);

    var wrap = document.createElement("div");
    wrap.className = "jg-wrap";
    var bar = document.createElement("div");
    bar.className = "jg-toolbar";
    var stage = document.createElement("div");
    stage.className = "jg-stage";
    stage.setAttribute("tabindex", "0");
    stage.setAttribute("aria-label", "JSON graph. Drag to pan, scroll to zoom.");
    var root$ = svg("svg", { class: "jg-svg", role: "img", "aria-label": "Graph of " + (opts && opts.title || "the JSON file") });
    var defs = svg("defs");
    var pattern = svg("pattern", { id: "jg-grid", width: "24", height: "24", patternUnits: "userSpaceOnUse" });
    pattern.appendChild(svg("path", { d: "M 24 0 L 0 0 0 24", class: "jg-gridline" }));
    defs.appendChild(pattern);
    root$.appendChild(defs);
    var bg = svg("rect", { width: "100%", height: "100%", fill: "url(#jg-grid)", class: "jg-bg" });
    root$.appendChild(bg);
    var viewport = svg("g");
    root$.appendChild(viewport);
    stage.appendChild(root$);
    var hint = document.createElement("p");
    hint.className = "jg-hint";
    hint.textContent = "Drag to pan · scroll or pinch to zoom · click a key node to fold or unfold it";
    wrap.appendChild(bar);
    wrap.appendChild(stage);
    wrap.appendChild(hint);
    container.appendChild(wrap);

    var view = { x: 24, y: 24, k: 0.9 };
    var size = { width: 0, height: 0 };
    function apply() { viewport.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")"); }

    function render() {
      size = layout(root);
      while (viewport.firstChild) viewport.removeChild(viewport.firstChild);
      var edgesG = svg("g", { class: "jg-edges" });
      var nodesG = svg("g", { class: "jg-nodes" });
      viewport.appendChild(edgesG);
      viewport.appendChild(nodesG);
      (function draw(n) {
        visibleChildren(n).forEach(function (c) {
          var x1 = n.x + n.w, y1 = n.y + n.h / 2, x2 = c.x, y2 = c.y + c.h / 2, mx = (x1 + x2) / 2;
          edgesG.appendChild(svg("path", { d: "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2, class: "jg-edge" }));
          draw(c);
        });
        var g = svg("g", { class: "jg-node jg-" + n.type + (n.collapsed ? " jg-collapsed" : ""), transform: "translate(" + n.x + "," + n.y + ")", "data-id": n.id });
        g.appendChild(svg("rect", { width: n.w, height: n.h, rx: n.type === "key" ? 6 : 4 }));
        if (n.type === "object") {
          n.lines.forEach(function (l, i) {
            var t = svg("text", { x: PAD_X, y: PAD_Y + i * ROW + 14 });
            var k = svg("tspan", { class: "jg-k" }); k.textContent = l.key;
            var v = svg("tspan", { class: "jg-v jg-" + l.kind }); v.textContent = l.value;
            t.appendChild(k); t.appendChild(v);
            if (l.full !== l.value) { var tt = svg("title"); tt.textContent = l.key + l.full; t.appendChild(tt); }
            g.appendChild(t);
          });
        } else if (n.type === "key") {
          var t = svg("text", { x: PAD_X, y: PAD_Y + 14 });
          var a = svg("tspan", { class: "jg-label" }); a.textContent = n.label + " ";
          var b = svg("tspan", { class: "jg-count" }); b.textContent = n.count;
          t.appendChild(a); t.appendChild(b);
          g.appendChild(t);
          var sign = svg("text", { x: n.w - PAD_X - 6, y: PAD_Y + 14, class: "jg-sign" });
          sign.textContent = n.children.length ? (n.collapsed ? "+" : "−") : "";
          g.appendChild(sign);
          if (n.children.length) {
            g.setAttribute("role", "button");
            g.setAttribute("tabindex", "0");
            g.setAttribute("aria-label", (n.collapsed ? "Unfold " : "Fold ") + n.label);
            var toggle = function (ev) {
              ev.stopPropagation();
              // Keep the clicked node where it is on screen while the layout changes.
              var sx = view.x + n.x * view.k, sy = view.y + n.y * view.k;
              n.collapsed = !n.collapsed;
              render();
              view.x = sx - n.x * view.k;
              view.y = sy - n.y * view.k;
              apply();
              var again = viewport.querySelector('[data-id="' + n.id + '"]');
              if (again) again.focus();
            };
            g.addEventListener("click", toggle);
            g.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(ev); } });
          }
        } else {
          var tv = svg("text", { x: PAD_X, y: PAD_Y + 14, class: "jg-v jg-" + kind(n.value) });
          tv.textContent = n.shown;
          if (n.full !== n.shown) { var ttv = svg("title"); ttv.textContent = n.full; tv.appendChild(ttv); }
          g.appendChild(tv);
        }
        nodesG.appendChild(g);
      })(root);
      apply();
    }

    function fit() {
      var r = stage.getBoundingClientRect();
      var k = Math.min((r.width - 48) / size.width, (r.height - 48) / size.height, 1);
      view.k = Math.max(0.05, k);
      view.x = (r.width - size.width * view.k) / 2;
      view.y = Math.max(24, (r.height - size.height * view.k) / 2);
      apply();
    }
    function zoomAt(px, py, factor) {
      var k = Math.min(3, Math.max(0.05, view.k * factor));
      view.x = px - (px - view.x) * (k / view.k);
      view.y = py - (py - view.y) * (k / view.k);
      view.k = k;
      apply();
    }
    function button(text, title, fn) {
      var b = document.createElement("button");
      b.type = "button"; b.className = "sg-btn"; b.textContent = text; b.title = title;
      b.addEventListener("click", fn);
      bar.appendChild(b);
    }
    button("Zoom in", "Zoom in", function () { var r = stage.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 1.25); });
    button("Zoom out", "Zoom out", function () { var r = stage.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 0.8); });
    button("Fit graph", "Show the whole graph", fit);
    button("Start", "Go back to the first node", function () { home(); });
    button("Unfold all", "Unfold every key node", function () {
      (function walk(n) { n.collapsed = false; n.children.forEach(walk); })(root); render(); home();
    });
    button("Fold all", "Fold every key node", function () {
      (function walk(n) { if (n.type === "key" && n.children.length) n.collapsed = true; n.children.forEach(walk); })(root); render(); home();
    });

    // Pan with mouse, pen or one finger; pinch with two fingers.
    var pointers = {}, last = null, pinch = null;
    stage.addEventListener("pointerdown", function (ev) {
      if (ev.target.closest && ev.target.closest(".jg-key")) return;
      stage.setPointerCapture(ev.pointerId);
      pointers[ev.pointerId] = { x: ev.clientX, y: ev.clientY };
      last = { x: ev.clientX, y: ev.clientY };
      stage.classList.add("jg-grabbing");
    });
    stage.addEventListener("pointermove", function (ev) {
      if (!pointers[ev.pointerId]) return;
      pointers[ev.pointerId] = { x: ev.clientX, y: ev.clientY };
      var ids = Object.keys(pointers);
      if (ids.length === 2) {
        var a = pointers[ids[0]], b = pointers[ids[1]];
        var d = Math.hypot(a.x - b.x, a.y - b.y);
        var r = stage.getBoundingClientRect();
        if (pinch) zoomAt((a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top, d / pinch);
        pinch = d;
        return;
      }
      view.x += ev.clientX - last.x;
      view.y += ev.clientY - last.y;
      last = { x: ev.clientX, y: ev.clientY };
      apply();
    });
    function end(ev) {
      delete pointers[ev.pointerId];
      pinch = null;
      var ids = Object.keys(pointers);
      last = ids.length ? pointers[ids[0]] : null;
      if (!ids.length) stage.classList.remove("jg-grabbing");
    }
    stage.addEventListener("pointerup", end);
    stage.addEventListener("pointercancel", end);
    stage.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var r = stage.getBoundingClientRect();
      zoomAt(ev.clientX - r.left, ev.clientY - r.top, Math.exp(-ev.deltaY * 0.0015));
    }, { passive: false });
    stage.addEventListener("keydown", function (ev) {
      var r = stage.getBoundingClientRect(), step = 60;
      if (ev.key === "+" || ev.key === "=") zoomAt(r.width / 2, r.height / 2, 1.2);
      else if (ev.key === "-") zoomAt(r.width / 2, r.height / 2, 1 / 1.2);
      else if (ev.key === "ArrowLeft") { view.x += step; apply(); }
      else if (ev.key === "ArrowRight") { view.x -= step; apply(); }
      else if (ev.key === "ArrowUp") { view.y += step; apply(); }
      else if (ev.key === "ArrowDown") { view.y -= step; apply(); }
      else return;
      ev.preventDefault();
    });

    function home() {
      var r = stage.getBoundingClientRect();
      var k = Math.min((r.width - 48) / size.width, (r.height - 48) / size.height);
      if (k >= 0.7) { fit(); return; }
      view.k = 0.9;
      view.x = 24;
      view.y = (r.height || 600) / 2 - (root.y + root.h / 2) * view.k;
      apply();
    }
    render();
    home();
    return { fit: fit };
  }

  return { mount: mount };
})();
