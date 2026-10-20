// STIX graph view: draws a STIX 2.1 bundle the way the OASIS STIX Visualizer
// does (vis-network, OASIS icons and physics, relationship objects as edges,
// embedded *_ref properties as edges), with its Selected Node, Linked Nodes
// and Legend panels.
var StixGraph = (function () {
  "use strict";

  // [property, edge label, true = edge points to the referenced object]
  var EMBEDDED = {
    "*": [["object_marking_refs", "applies-to", false]],
    "grouping": [["object_refs", "refers-to", true]],
    "note": [["object_refs", "refers-to", true]],
    "observed-data": [["object_refs", "refers-to", true]],
    "opinion": [["object_refs", "refers-to", true]],
    "sighting": [["sighting_of_ref", "sighting-of", true], ["observed_data_refs", "observed", true],
                 ["where_sighted_refs", "saw", false]],
    "file": [["parent_directory_ref", "parent-of", false]],
    "directory": [["contains_refs", "contains", true]]
  };

  function displayName(o) {
    if (o.name) return o.name;
    if (o.abstract) return o.abstract;
    if (o.type === "directory" && o.path) return o.path;
    if (o.type === "observed-data") return "Observed data (" + (o.number_observed || 1) + ")";
    if (o.type === "marking-definition" && o.definition && o.definition.statement) return o.definition.statement;
    return o.type;
  }

  // Only http(s) addresses become links.
  function safeUrl(u) {
    try {
      var x = new URL(String(u), window.location.href);
      return (x.protocol === "https:" || x.protocol === "http:") ? x.href : null;
    } catch (e) { return null; }
  }

  function truncate(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function stripCitations(t) {
    return String(t).replace(/\(Citation:[^)]*\)/g, "").replace(/\[([^\]]+)\]\(https?:\/\/attack\.mitre\.org[^)]*\)/g, "$1");
  }

  // Readable names for ATT&CK's custom object types.
  var TYPE_NAMES = {
    "x-mitre-detection-strategy": "ATT&CK detection strategy",
    "x-mitre-analytic": "ATT&CK analytic",
    "x-mitre-data-component": "ATT&CK data component"
  };
  // Names of the sub-areas a mixed group is split into.
  var KIND_NAMES = {
    "indicator:sigma": "SigmaHQ rules",
    "indicator:stix": "STIX indicators",
    "x-mitre-detection-strategy": "Detection strategies",
    "x-mitre-analytic": "Analytics",
    "x-mitre-data-component": "Data components",
    "intrusion-set": "Groups",
    "campaign": "Campaigns",
    "malware": "Malware",
    "tool": "Tools"
  };
  function typeName(t) { return TYPE_NAMES[t] || t.charAt(0).toUpperCase() + t.slice(1); }

  function iconFor(type) {
    return STIX_ICONS[type] || STIX_ICONS["custom-object"];
  }

  function refs(o, prop) {
    var v = o[prop];
    if (v === undefined || v === null) return [];
    return Array.isArray(v) ? v : [v];
  }

  function buildGraph(bundle) {
    var byId = Object.create(null);
    bundle.objects.forEach(function (o) { byId[o.id] = o; });
    var nodes = [], edges = [], types = Object.create(null);
    bundle.objects.forEach(function (o) {
      if (o.type === "relationship") return;
      types[o.type] = (types[o.type] || 0) + 1;
      nodes.push({ id: o.id, group: o.type, title: displayName(o) + "\n" + typeName(o.type), shape: "circularImage",
                   image: iconFor(o.type), brokenImage: STIX_ICONS["custom-object"],
                   label: truncate(displayName(o), 28),
                   // The copyright marking points at every ATT&CK object; it starts hidden
                   // so its edges do not pull the layout into one knot.
                   hidden: o.type === "marking-definition", physics: o.type !== "marking-definition" });
    });
    var n = 0;
    bundle.objects.forEach(function (o) {
      if (o.type === "relationship") {
        if (byId[o.source_ref] && byId[o.target_ref]) {
          edges.push({ id: "e" + (n++), from: o.source_ref, to: o.target_ref, rel: o.relationship_type,
                       stixId: o.id, title: o.relationship_type,
                       desc: o.description ? stripCitations(o.description).replace(/`/g, "") : "",
                       cites: (o.external_references || []).filter(function (r) { return safeUrl(r.url); }) });
        }
        return;
      }
      (EMBEDDED["*"].concat(EMBEDDED[o.type] || [])).forEach(function (spec) {
        refs(o, spec[0]).forEach(function (r) {
          if (!byId[r] || byId[r].type === "relationship") return;
          var from = spec[2] ? o.id : r, to = spec[2] ? r : o.id;
          edges.push({ id: "e" + (n++), from: from, to: to, rel: spec[1], title: spec[1] });
        });
      });
    });
    // Clusters: each grouping (Associated APTs, Malware, TTPs, ...) is placed on a
    // ring around the binary with its members gathered around it, and the
    // layout keeps them apart: long springs from a grouping to the binary,
    // short springs to its members, and members' own direct links to the
    // binary drawn but not pulling.
    var report = bundle.objects.filter(function (o) { return o.type === "report"; })[0];
    var center = report && report.object_refs ? report.object_refs[0] : null;
    var groups = bundle.objects.filter(function (o) { return o.type === "grouping"; }).map(function (gr) {
      return { id: gr.id, name: gr.name, members: (gr.object_refs || []).filter(function (r) { return byId[r] && r !== center && byId[r].type !== "relationship"; }) };
    });
    var memberOf = Object.create(null);
    groups.forEach(function (gr, i) { gr.members.forEach(function (m) { if (!(m in memberOf)) memberOf[m] = i; }); });
    // ATT&CK analytics and data components belong with the detection strategies
    // that use them: lay them out inside that group's area.
    groups.forEach(function (gr, i) {
      gr.extra = [];
      if (!gr.members.some(function (m) { return byId[m].type === "x-mitre-detection-strategy"; })) return;
      bundle.objects.forEach(function (o) {
        if ((o.type === "x-mitre-analytic" || o.type === "x-mitre-data-component") && !(o.id in memberOf)) {
          memberOf[o.id] = i;
          gr.extra.push(o.id);
        }
      });
    });
    // A group that holds several kinds of object (Associated Detections: SigmaHQ
    // rules, ATT&CK detection strategies, analytics, data components) is split
    // into one sub-area per kind. Each sub-area gathers around its own hidden,
    // fixed anchor, placed like petals around the group's hub.
    function kindOf(id) {
      var o = byId[id];
      return o.type === "indicator" && o.pattern_type ? o.type + ":" + o.pattern_type : o.type;
    }
    groups.forEach(function (gr) {
      var subs = {}, order = [];
      gr.members.concat(gr.extra).forEach(function (m) {
        var k = kindOf(m);
        if (!subs[k]) { subs[k] = { kind: k, ids: [] }; order.push(k); }
        subs[k].ids.push(m);
      });
      gr.subs = order.length > 1 ? order.map(function (k) { return subs[k]; }) : [];
      gr.subs.forEach(function (sub, i) {
        sub.id = gr.id + "#sub" + i;
        sub.name = KIND_NAMES[sub.kind] || typeName(sub.kind.split(":")[0]);
        sub.size = 40 + 40 * Math.sqrt(sub.ids.length);
      });
      if (!gr.subs.length) { gr.radius = 70 + 55 * Math.sqrt(gr.members.length + gr.extra.length + 1); return; }
      // distance from the hub at which every sub-area fits in its own wedge
      var gap = 90, d = gr.subs.reduce(function (t, sub) { return Math.max(t, sub.size + gap); }, 0);
      function widths(dist) {
        return gr.subs.map(function (sub) { return 2 * Math.asin(Math.min(1, (sub.size + gap / 2) / dist)); });
      }
      while (widths(d).reduce(function (t, w) { return t + w; }, 0) > 2 * Math.PI) d += 20;
      gr.subDist = d;
      gr.subWidths = widths(d);
      gr.radius = d + gr.subs.reduce(function (t, sub) { return Math.max(t, sub.size); }, 0) + 30;
    });
    // Ring big enough that every cluster fits around it without touching.
    var R = Math.max(520, groups.reduce(function (t, gr) { return t + 2 * gr.radius + 120; }, 0) / (2 * Math.PI));
    var pos = Object.create(null);
    if (center) pos[center] = { x: 0, y: 0 };
    var acc = 0, total = groups.reduce(function (t, gr) { return t + 2 * gr.radius + 120; }, 0);
    groups.forEach(function (gr, i) {
      // each cluster gets an arc of the ring in proportion to its size
      var share = (2 * gr.radius + 120) / total;
      var a = 2 * Math.PI * (acc + share / 2) - Math.PI / 2;
      acc += share;
      var hx = (R + gr.radius) * Math.cos(a), hy = (R + gr.radius) * Math.sin(a);
      pos[gr.id] = { x: hx, y: hy };
      gr.ring = R + gr.radius;
      function spiral(ids, cx, cy, step) {
        ids.forEach(function (m, j) {
          if (memberOf[m] !== i) return;
          var r = step * Math.sqrt(j + 1), t = j * 2.39996;
          pos[m] = { x: cx + r * Math.cos(t), y: cy + r * Math.sin(t) };
        });
      }
      if (!gr.subs.length) { spiral(gr.members.concat(gr.extra), hx, hy, 55); return; }
      // Sub-areas side by side around the hub, the largest on the side facing
      // away from the binary and the smaller ones either side of it, so the
      // gap left over faces the binary.
      var bySize = gr.subs.map(function (sub, k) { return k; })
        .sort(function (x, y) { return gr.subs[y].ids.length - gr.subs[x].ids.length; });
      var seq = [];
      bySize.forEach(function (k, n) { if (n % 2) seq.unshift(k); else seq.push(k); });
      var used = gr.subWidths.reduce(function (t, w) { return t + w; }, 0);
      var slack = (2 * Math.PI - used) / gr.subs.length;
      var angle = {}, t0 = 0;
      seq.forEach(function (k) { angle[k] = t0 + gr.subWidths[k] / 2; t0 += gr.subWidths[k] + slack; });
      var turn = a - angle[bySize[0]];
      gr.subs.forEach(function (sub, k) {
        var ta = angle[k] + turn;
        pos[sub.id] = { x: hx + gr.subDist * Math.cos(ta), y: hy + gr.subDist * Math.sin(ta) };
        spiral(sub.ids, pos[sub.id].x, pos[sub.id].y, 40);
      });
    });
    var subOf = {}, anchorNodes = [], anchorEdges = [];
    groups.forEach(function (gr, i) {
      gr.subs.forEach(function (sub) {
        anchorNodes.push({ id: sub.id, hidden: true, fixed: { x: true, y: true }, x: pos[sub.id].x, y: pos[sub.id].y, mass: 1 });
        sub.ids.forEach(function (m) {
          if (memberOf[m] !== i) return;
          subOf[m] = sub.id;
          anchorEdges.push({ id: sub.id + ">" + m, from: sub.id, to: m, hidden: true, length: 40 + 6 * Math.sqrt(sub.ids.length) });
        });
      });
    });
    var isGroup = Object.create(null);
    groups.forEach(function (gr) { isGroup[gr.id] = true; });
    var groupById = Object.create(null);
    groups.forEach(function (gr) { groupById[gr.id] = gr; });
    nodes.forEach(function (nd) {
      if (pos[nd.id]) { nd.x = pos[nd.id].x; nd.y = pos[nd.id].y; }
      // The binary and the group hubs are anchored on the ring so the clusters
      // stay apart; everything else moves freely around them.
      if (nd.id === center || groupById[nd.id]) nd.fixed = { x: true, y: true };
    });
    edges.forEach(function (e) {
      var ends = [e.from, e.to];
      // The copyright marking links to every ATT&CK object. Its links are drawn
      // but must not act as springs, or they pull every object towards it.
      if (byId[e.from].type === "marking-definition" || byId[e.to].type === "marking-definition") { e.physics = false; return; }
      if (isGroup[e.from] && e.to === center) e.length = groupById[e.from].ring;
      else if (isGroup[e.from] && e.rel === "refers-to") e.length = 60 + 8 * Math.sqrt(groupById[e.from].members.length);
      else if (center && ends.indexOf(center) !== -1 && (memberOf[e.from] !== undefined || memberOf[e.to] !== undefined)) e.physics = false;
      else if (memberOf[e.from] !== undefined && memberOf[e.to] !== undefined && memberOf[e.from] !== memberOf[e.to]) e.physics = false;
      // inside a split group, members hang from their sub-area's anchor, not the
      // hub, and links between sub-areas are drawn without pulling them together
      if (isGroup[e.from] && subOf[e.to]) e.physics = false;
      if (subOf[e.from] && subOf[e.to] && subOf[e.from] !== subOf[e.to]) e.physics = false;
    });
    return { byId: byId, nodes: nodes, edges: edges, types: types, groups: groups, center: center, home: pos,
             anchorNodes: anchorNodes, anchorEdges: anchorEdges,
             anchors: [center].concat(groups.map(function (gr) { return gr.id; }),
                                      anchorNodes.map(function (n) { return n.id; })).filter(Boolean) };
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else if (k === "class") node.className = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      if (c !== null && c !== undefined) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  // Render the property list of the selected object.
  function propertyList(o, onRef) {
    var dl = el("dl", { class: "sg-props" });
    var order = ["type", "name", "id", "description", "created", "modified"];
    var keys = order.filter(function (k) { return k in o; })
      .concat(Object.keys(o).filter(function (k) { return order.indexOf(k) === -1 && k !== "spec_version"; }));
    keys.forEach(function (k) {
      var v = o[k], dd = el("dd");
      if (k === "external_references") {
        dd.appendChild(el("ul", {}, v.map(function (r) {
          var label = r.source_name + (r.external_id ? " " + r.external_id : "");
          return el("li", {}, [safeUrl(r.url) ? el("a", { href: safeUrl(r.url), target: "_blank", rel: "noopener noreferrer", text: label }) : label,
                               r.description && !r.url ? ": " + r.description : ""]);
        })));
      } else if (/_refs?$/.test(k) && (typeof v === "string" || Array.isArray(v))) {
        var list = Array.isArray(v) ? v : [v];
        dd.appendChild(el("span", {}, list.slice(0, 60).map(function (r) {
          var b = el("button", { class: "sg-ref", type: "button", text: r.split("--")[0] + "--" + r.split("--")[1].slice(0, 8) + "..." });
          b.addEventListener("click", function () { onRef(r); });
          return b;
        }).concat(list.length > 60 ? [" +" + (list.length - 60) + " more"] : [])));
      } else if (k === "pattern" && o.pattern_type === "sigma") {
        dd.appendChild(el("details", {}, [el("summary", { text: "Show Sigma rule" }), el("pre", { class: "sg-pre", text: v })]));
      } else if (typeof v === "string") {
        var text = k === "description" ? stripCitations(v) : v;
        if (text.length > 600) {
          dd.appendChild(el("span", { text: text.slice(0, 600) + "... " }));
          var more = el("details", {}, [el("summary", { text: "Show all" }), el("pre", { class: "sg-pre", text: text })]);
          dd.appendChild(more);
        } else dd.textContent = text;
      } else {
        dd.appendChild(el("pre", { class: "sg-pre", text: JSON.stringify(v, null, 2) }));
      }
      dl.appendChild(el("dt", { text: k }));
      dl.appendChild(dd);
    });
    return dl;
  }

  // What the relationships of a node say, in ATT&CK's words, with their sources.
  // The binary itself is left out: its statements are in the Threat Intel view.
  function relationContext(g, id) {
    if (id === g.center) return null;
    var seen = {}, items = [];
    g.edges.forEach(function (e) {
      if (!e.desc || (e.from !== id && e.to !== id)) return;
      var other = g.byId[e.from === id ? e.to : e.from];
      var key = e.from + ">" + e.to + ">" + e.desc;
      if (!other || seen[key]) return;
      seen[key] = true;
      items.push({ e: e, other: other, out: e.from === id });
    });
    if (!items.length) return null;
    var box = el("div", { class: "sg-context" }, [el("h5", { text: "What ATT&CK says (" + items.length + ")" })]);
    items.slice(0, 8).forEach(function (it) {
      var who = it.out ? it.e.rel + " " + displayName(it.other) : displayName(it.other) + " " + it.e.rel + " this";
      var p = el("p", { class: "sg-stmt" }, [el("span", { class: "sg-rel", text: who }), el("br"), it.e.desc]);
      if (it.e.cites.length) {
        p.appendChild(el("span", { class: "sg-cites" }, [" "].concat(it.e.cites.slice(0, 6).map(function (c) {
          return el("a", { href: safeUrl(c.url), target: "_blank", rel: "noopener noreferrer", text: "[" + c.source_name + "]" });
        }))));
      }
      box.appendChild(p);
    });
    if (items.length > 8) box.appendChild(el("p", { class: "sg-empty", text: "+" + (items.length - 8) + " more in the linked nodes below." }));
    return box;
  }

  function mount(container, bundle) {
    var g = buildGraph(bundle);
    var hiddenTypes = { "marking-definition": true };
    var canvas = el("div", { class: "sg-canvas", role: "img", "aria-label": "STIX relationship graph" });
    var status = el("p", { class: "sg-status", text: "Laying out " + g.nodes.length + " objects..." });
    var toolbar = el("div", { class: "sg-toolbar" });
    var selected = el("div", { class: "sg-panel" }, [el("h4", { text: "Selected Node" }),
      el("p", { class: "sg-empty", text: "Click a node to see its properties." })]);
    var linked = el("div", { class: "sg-panel" }, [el("h4", { text: "Linked Nodes" }),
      el("p", { class: "sg-empty", text: "Incoming and outgoing edges of the selected node." })]);
    var legend = el("div", { class: "sg-panel" }, [el("h4", { text: "Legend" }),
      el("p", { class: "sg-hint", text: "Click a type to hide or show its nodes. The ATT&CK copyright marking starts hidden: it links to every ATT&CK object." })]);
    var layout = el("div", { class: "sg-layout" }, [
      el("div", { class: "sg-stage" }, [toolbar, canvas, status]),
      el("div", { class: "sg-side" }, [selected, linked, legend])]);
    container.appendChild(layout);

    var nodes = new vis.DataSet(g.nodes.concat(g.anchorNodes));
    var edges = new vis.DataSet(g.edges.map(function (e) { return Object.assign({}, e, { label: "" }); }).concat(g.anchorEdges));
    toolbar.appendChild(el("span", { class: "sg-hint sg-tip", text: "Drag a node to place it; it stays where you drop it. Double-click to release it." }));
    var network = new vis.Network(canvas, { nodes: nodes, edges: edges }, {
      nodes: { color: { border: "#1b1d2b" }, font: { size: 14, color: getComputedStyle(document.documentElement).getPropertyValue("--fg").trim() || "#1b1d2b", strokeWidth: 3, strokeColor: getComputedStyle(document.documentElement).getPropertyValue("--sg-bg").trim() || "#f1f1f1" },
               borderWidth: 2, size: 20,
               chosen: { node: function (values, id, selected) { if (selected) { values.shadow = true; values.shadowX = values.shadowY = 6; values.borderWidth = 4; } } } },
      edges: { arrows: { to: { enabled: true, scaleFactor: 0.6 } }, width: 2, color: { color: "#9a9aa8", highlight: "#3e228a", hover: "#3e228a" },
               font: { size: 16, align: "middle", color: "#555869", strokeWidth: 3 }, smooth: { type: "continuous" } },
      // Same solver as the OASIS visualizer, damped so neighbours follow a dragged
      // node smoothly instead of jumping.
      physics: { solver: "barnesHut",
                 barnesHut: { theta: 0.6, gravitationalConstant: -5000, centralGravity: 0, springConstant: 0.02,
                              springLength: 160, damping: 0.6, avoidOverlap: 0.3 },
                 maxVelocity: 12, minVelocity: 0.75, timestep: 0.35,
                 stabilization: { enabled: true, iterations: 600, updateInterval: 25, fit: true } },
      interaction: { hover: true, tooltipDelay: 120, navigationButtons: false, keyboard: false, dragNodes: true,
                     multiselect: false, zoomSpeed: 0.6 }
    });
    var live = true;
    // Shaded, labelled area behind each grouping's cluster.
    // Mid-tone hues that read on both the light and the dark canvas.
    var HALO = ["#7c5cd6", "#2f9e63", "#d07a1f", "#3d82d6", "#c2457f", "#1aa39a", "#8a8fa3", "#c79a1a", "#9a6cf0", "#e0485f"];
    var haloOn = true;
    var measure = document.createElement("canvas").getContext("2d");

    // The shaded area of each group and of its sub-areas, in canvas
    // coordinates. Drawing and fitting share it, so a fit keeps the areas and
    // their names on screen, not only the nodes.
    function haloShapes() {
      var out = [];
      g.groups.forEach(function (gr, i) {
        var ids = [gr.id].concat(gr.members, gr.extra).filter(function (id) { var nd = nodes.get(id); return nd && !nd.hidden; });
        if (ids.length < 2) return;
        var p = network.getPositions(ids), xs = 0, ys = 0;
        ids.forEach(function (id) { xs += p[id].x; ys += p[id].y; });
        var cx = xs / ids.length, cy = ys / ids.length, r = 0;
        ids.forEach(function (id) { r = Math.max(r, Math.hypot(p[id].x - cx, p[id].y - cy)); });
        var shape = { col: HALO[i % HALO.length], x: cx, y: cy, r: r + 42, name: gr.name + " (" + gr.members.length + ")", subs: [] };
        gr.subs.forEach(function (sub) {
          var sids = sub.ids.filter(function (id) { var nd = nodes.get(id); return nd && !nd.hidden; });
          if (!sids.length) return;
          var sp = network.getPositions(sids), sx = 0, sy = 0, sr = 0;
          sids.forEach(function (id) { sx += sp[id].x; sy += sp[id].y; });
          sx /= sids.length; sy /= sids.length;
          sids.forEach(function (id) { sr = Math.max(sr, Math.hypot(sp[id].x - sx, sp[id].y - sy)); });
          shape.subs.push({ x: sx, y: sy, r: sr + 34, name: sub.name + " (" + sids.length + ")" });
        });
        out.push(shape);
      });
      return out;
    }

    // Each name goes above its area. A group's name moves up over the names
    // of its own sub-areas; a name that would cover another group's name goes
    // below its area instead. fs is the group name size in canvas units.
    function placeLabels(shapes, fs) {
      var placed = [], out = [];
      function hits(b, list) {
        return list.some(function (o) { return b[0] < o[2] && o[0] < b[2] && b[1] < o[3] && o[1] < b[3]; });
      }
      function label(text, x, y, size, weight, col) {
        measure.font = weight + " " + size + "px 'IBM Plex Sans', Arial, sans-serif";
        var w = measure.measureText(text).width;
        return { text: text, x: x, y: y, font: measure.font, col: col, w: w, size: size,
                 at: function (ny) { this.y = ny; this.box = [x - w / 2 - 4, ny - size * 0.85, x + w / 2 + 4, ny + size * 0.3]; return this; } }.at(y);
      }
      shapes.forEach(function (s) {
        var others = placed.slice(), own = [];
        s.subs.forEach(function (sub) {
          var sfs = fs * 0.85, l = label(sub.name, sub.x, sub.y - sub.r - sfs * 0.5, sfs, 500, s.col);
          if (hits(l.box, placed)) l.at(sub.y + sub.r + sfs * 1.05);
          placed.push(l.box); own.push(l); out.push(l);
        });
        var g$ = label(s.name, s.x, s.y - s.r - fs * 0.5, fs, 600, s.col);
        for (var k = 0; k < own.length && hits(g$.box, own.map(function (l) { return l.box; })); k++) {
          var top = Math.min.apply(null, own.filter(function (l) { return hits(g$.box, [l.box]); }).map(function (l) { return l.box[1]; }));
          g$.at(top - fs * 0.4);
        }
        if (hits(g$.box, others)) g$.at(s.y + s.r + fs * 1.05);
        placed.push(g$.box); out.push(g$);
      });
      return out;
    }

    // labels stay about 13px on screen at any zoom
    function labelSize(scale) { return Math.max(16, 13 / scale); }

    network.on("beforeDrawing", function (ctx) {
      if (!haloOn) return;
      var shapes = haloShapes();
      shapes.forEach(function (s) {
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.r, 0, 2 * Math.PI);
        ctx.fillStyle = s.col + "14";
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.setLineDash([8, 6]);
        ctx.strokeStyle = s.col + "66";
        ctx.stroke();
        s.subs.forEach(function (sub) {
          ctx.beginPath();
          ctx.arc(sub.x, sub.y, sub.r, 0, 2 * Math.PI);
          ctx.fillStyle = s.col + "1f";
          ctx.fill();
          ctx.lineWidth = 1.5;
          ctx.setLineDash([3, 4]);
          ctx.strokeStyle = s.col + "99";
          ctx.stroke();
        });
        ctx.setLineDash([]);
      });
      ctx.textAlign = "center";
      placeLabels(shapes, labelSize(network.getScale())).forEach(function (l) {
        ctx.font = l.font;
        ctx.fillStyle = l.col;
        ctx.fillText(l.text, l.x, l.y);
      });
    });

    // Fit the nodes, their names, the group areas and the area names. vis
    // fits only the nodes, which cut names off at the canvas edge. On a small
    // canvas the names (13px on screen) cannot all fit, so the fit never zooms
    // out to less than 80% of the nodes-only fit.
    // A graph laid out in a hidden tab is fitted when the tab is shown.
    var fitPending = false;
    network.on("resize", function () { if (fitPending) fitAll(false); });
    function fitAll(animate) {
      var ids = nodes.getIds({ filter: function (n) { return !n.hidden; } });
      if (!ids.length) return;
      var W = canvas.clientWidth - 24, H = canvas.clientHeight - 24;
      fitPending = W <= 0 || H <= 0;
      if (fitPending) return;
      var p = network.getPositions(ids), shapes = haloOn ? haloShapes() : [];
      function grow(b, x0, y0, x1, y1) { return [Math.min(b[0], x0), Math.min(b[1], y0), Math.max(b[2], x1), Math.max(b[3], y1)]; }
      function scaleFor(b) { return Math.min(W / (b[2] - b[0]), H / (b[3] - b[1])); }
      measure.font = "14px arial";
      var nodeBox = [Infinity, Infinity, -Infinity, -Infinity];
      ids.forEach(function (id) {
        var label = nodes.get(id).label || "", half = Math.max(22, measure.measureText(label).width / 2);
        nodeBox = grow(nodeBox, p[id].x - half, p[id].y - 22, p[id].x + half, p[id].y + (label ? 42 : 22));
      });
      var box = nodeBox, scale = scaleFor(nodeBox), floor = 0.8 * scale;
      for (var k = 0; k < 3; k++) {
        box = nodeBox;
        shapes.forEach(function (s) { box = grow(box, s.x - s.r, s.y - s.r, s.x + s.r, s.y + s.r); });
        placeLabels(shapes, labelSize(scale)).forEach(function (l) { box = grow(box, l.box[0], l.box[1], l.box[2], l.box[3]); });
        scale = scaleFor(box);
      }
      if (scale < floor) { scale = floor; box = nodeBox; }
      network.moveTo({ position: { x: (box[0] + box[2]) / 2, y: (box[1] + box[3]) / 2 }, scale: scale,
                       animation: animate ? { duration: 400 } : false });
    }

    network.once("stabilizationIterationsDone", function () {
      status.hidden = true;
      if (!live) network.setOptions({ physics: { enabled: false } });
      fitAll(false);
    });
    network.on("stabilizationProgress", function (p) {
      status.textContent = "Laying out " + g.nodes.length + " objects... " + Math.round(100 * p.iterations / p.total) + "%";
    });

    // A dropped node stays where it is dropped (pinned); the springs to its
    // neighbours would otherwise pull it back to where it was. Double-click
    // releases it.
    var pinned = {};
    function pin(id, on) {
      if (on) pinned[id] = true; else delete pinned[id];
      nodes.update({ id: id, fixed: on ? { x: true, y: true } : false,
                     shapeProperties: { borderDashes: on ? [5, 4] : false }, borderWidth: on ? 3 : 2 });
    }
    // Dragging a split group's hub carries its sub-area anchors along.
    var subAnchorsOf = {}, dragFrom = null;
    g.groups.forEach(function (gr) { if (gr.subs.length) subAnchorsOf[gr.id] = gr.subs.map(function (sub) { return sub.id; }); });
    network.on("dragStart", function (params) {
      params.nodes.forEach(function (id) { nodes.update({ id: id, fixed: false }); });
      var hub = params.nodes.filter(function (id) { return subAnchorsOf[id]; })[0];
      dragFrom = hub ? { hub: hub, at: network.getPositions([hub])[hub], subs: network.getPositions(subAnchorsOf[hub]) } : null;
    });
    network.on("dragging", function () {
      if (!dragFrom) return;
      var now = network.getPositions([dragFrom.hub])[dragFrom.hub];
      var dx = now.x - dragFrom.at.x, dy = now.y - dragFrom.at.y;
      subAnchorsOf[dragFrom.hub].forEach(function (id) {
        network.moveNode(id, dragFrom.subs[id].x + dx, dragFrom.subs[id].y + dy);
      });
    });
    network.on("dragEnd", function (params) {
      params.nodes.forEach(function (id) { pin(id, true); });
    });
    var anchored = {};
    g.anchors.forEach(function (id) { anchored[id] = true; });
    network.on("doubleClick", function (params) {
      params.nodes.forEach(function (id) {
        if (!pinned[id]) return;
        pin(id, false);
        if (anchored[id]) nodes.update({ id: id, fixed: { x: true, y: true } });  // back to an anchor, but where it is now
      });
      if (params.nodes.length && live) network.startSimulation();
    });

    // Toolbar.
    var showLabels = true;
    toolbar.querySelector(".sg-tip").textContent = "Drag a node or a whole group (by its hub) to place it; it stays where you drop it. Double-click a node to release it.";
    function btn(text, title, fn) {
      var b = el("button", { type: "button", class: "sg-btn", title: title, text: text });
      b.addEventListener("click", fn);
      toolbar.appendChild(b);
      return b;
    }
    function applyLabels() {
      nodes.update(g.nodes.map(function (n) {
        return { id: n.id, label: showLabels ? truncate(displayName(g.byId[n.id]), 28) : "" };
      }));
    }
    btn("Fit graph", "Zoom to show every node and group", function () { fitAll(true); });
    var labelBtn = btn("Hide names", "Show or hide the name under every node (hover an edge to see its type)", function () {
      showLabels = !showLabels;
      labelBtn.textContent = showLabels ? "Hide names" : "Show names";
      applyLabels();
    });
    var haloBtn = btn("Hide group areas", "Show or hide the shaded area behind each group", function () {
      haloOn = !haloOn;
      haloBtn.textContent = haloOn ? "Hide group areas" : "Show group areas";
      network.redraw();
    });
    btn("Re-arrange", "Put the groups back on the ring, release every dropped node and run the layout again", function () {
      Object.keys(pinned).forEach(function (id) { pin(id, false); });
      nodes.update(g.anchors.map(function (id) {
        return { id: id, x: g.home[id].x, y: g.home[id].y, fixed: { x: true, y: true } };
      }));
      status.hidden = false;
      status.textContent = "Re-arranging...";
      network.setOptions({ physics: { enabled: true } });
      network.stabilize(400);
      network.once("stabilized", function () {
        status.hidden = true;
        if (!live) network.setOptions({ physics: { enabled: false } });
      });
    });
    var liveBtn = btn("Live physics: on", "On: neighbours move around the node you drag. Off: only the dragged node moves.", function () {
      live = !live;
      liveBtn.textContent = "Live physics: " + (live ? "on" : "off");
      liveBtn.setAttribute("aria-pressed", live ? "true" : "false");
      network.setOptions({ physics: { enabled: live } });
    });
    liveBtn.setAttribute("aria-pressed", "true");
    toolbar.appendChild(el("span", { class: "sg-count", text: g.nodes.length + " nodes · " + g.edges.length + " edges" }));


    function focus(id) {
      if (!g.byId[id] || g.byId[id].type === "relationship") return;
      network.selectNodes([id]);
      network.focus(id, { scale: Math.max(network.getScale(), 0.7), animation: { duration: 400 } });
      select(id);
    }

    function select(id) {
      var o = g.byId[id];
      selected.textContent = "";
      linked.textContent = "";
      selected.appendChild(el("h4", { text: "Selected Node" }));
      linked.appendChild(el("h4", { text: "Linked Nodes" }));
      if (!o) {
        selected.appendChild(el("p", { class: "sg-empty", text: "Click a node to see its properties." }));
        linked.appendChild(el("p", { class: "sg-empty", text: "Incoming and outgoing edges of the selected node." }));
        return;
      }
      selected.appendChild(el("div", { class: "sg-title" }, [el("img", { src: iconFor(o.type), alt: "", width: "28", height: "28" }),
        el("div", {}, [el("b", { text: displayName(o) }), el("span", { class: "sg-type", text: TYPE_NAMES[o.type] ? TYPE_NAMES[o.type] + " · " + o.type : o.type })])]));
      var ctx = relationContext(g, id);
      if (ctx) selected.appendChild(ctx);
      selected.appendChild(propertyList(o, focus));
      var inc = g.edges.filter(function (e) { return e.to === id; });
      var out = g.edges.filter(function (e) { return e.from === id; });
      [["Incoming edges", inc, "from"], ["Outgoing edges", out, "to"]].forEach(function (part) {
        linked.appendChild(el("h5", { text: part[0] + " (" + part[1].length + ")" }));
        if (!part[1].length) { linked.appendChild(el("p", { class: "sg-empty", text: "None" })); return; }
        linked.appendChild(el("ul", { class: "sg-links" }, part[1].slice(0, 150).map(function (e) {
          var other = g.byId[e[part[2]]];
          var b = el("button", { type: "button", class: "sg-link", title: e.desc || "" }, [el("img", { src: iconFor(other.type), alt: "", width: "16", height: "16" }),
            el("span", { class: "sg-rel", text: e.rel }), " " + displayName(other)]);
          b.addEventListener("click", function () { focus(other.id); });
          return el("li", {}, [b]);
        }).concat(part[1].length > 150 ? [el("li", { class: "sg-empty", text: "+" + (part[1].length - 150) + " more" })] : [])));
      });
    }

    network.on("click", function (params) {
      if (params.nodes.length) select(params.nodes[0]);
    });

    // Legend with type toggles.
    var list = el("ul", { class: "sg-legend" });
    Object.keys(g.types).sort().forEach(function (t) {
      var b = el("button", { type: "button", class: "sg-legend-item", "aria-pressed": hiddenTypes[t] ? "false" : "true",
                             title: hiddenTypes[t] ? "Hidden at start: click to show" : "Click to hide" }, [
        el("img", { src: iconFor(t), alt: "", width: "26", height: "26" }),
        el("span", { text: typeName(t) }), el("span", { class: "sg-legend-n", text: String(g.types[t]) })]);
      b.addEventListener("click", function () {
        hiddenTypes[t] = !hiddenTypes[t];
        b.setAttribute("aria-pressed", hiddenTypes[t] ? "false" : "true");
        nodes.update(g.nodes.filter(function (n) { return n.group === t; }).map(function (n) {
          return { id: n.id, hidden: !!hiddenTypes[t], physics: !hiddenTypes[t] };
        }));
      });
      list.appendChild(el("li", {}, [b]));
    });
    legend.appendChild(list);

    // Open on the binary itself, like a reader would start.
    var report = bundle.objects.filter(function (o) { return o.type === "report"; })[0];
    if (report && report.object_refs && report.object_refs[0]) {
      network.once("stabilizationIterationsDone", function () { network.selectNodes([report.object_refs[0]]); select(report.object_refs[0]); });
    }
    // Light / dark switch: the graph library takes its label colours as options.
    function themeOptions() {
      var cs = getComputedStyle(document.documentElement);
      return { nodes: { color: { border: cs.getPropertyValue("--sg-node-border").trim() || "#1b1d2b" },
                        font: { color: cs.getPropertyValue("--fg").trim() || "#1b1d2b", strokeColor: cs.getPropertyValue("--sg-bg").trim() || "#f1f1f1" } } };
    }
    document.addEventListener("themechange", function () {
      if (document.body.contains(canvas)) network.setOptions(themeOptions());
    });
    container.stixNetwork = network;
    return network;
  }

  return { mount: mount, buildGraph: buildGraph };
})();
