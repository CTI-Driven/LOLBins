// LOLBins CTI-Driven: renders every binary from lolbins/index.json and the
// detail files in lolbins/details/. The STIX and JSON graphs are drawn in
// the page (js/stixgraph.js, js/jsongraph.js) from the files published with
// the site, so nothing depends on a third-party viewer.
(function () {
  "use strict";

  var cache = Object.create(null);

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

  // Only http(s) addresses become links; anything else (javascript:, data:) is shown as text.
  function safeUrl(u) {
    try {
      var x = new URL(String(u), window.location.href);
      return (x.protocol === "https:" || x.protocol === "http:") ? x.href : null;
    } catch (e) { return null; }
  }

  // Builds an SVG from a fixed markup string without innerHTML.
  function svgFrom(markup) {
    var doc = new DOMParser().parseFromString(markup, "image/svg+xml");
    return document.importNode(doc.documentElement, true);
  }

  function link(href, text) {
    var ok = safeUrl(href);
    if (!ok) return el("span", { text: text || href });
    return el("a", { href: ok, target: "_blank", rel: "noopener noreferrer", text: text || href });
  }

  function fileLink(path) {
    return el("a", { href: path, download: path.split("/").pop(), target: "_blank", rel: "noopener", class: "file-link" },
      [el("code", { text: path })]);
  }

  function getJSON(path) {
    if (!cache[path]) {
      cache[path] = fetch(path).then(function (r) {
        if (!r.ok) throw new Error(path + ": HTTP " + r.status);
        return r.json();
      });
    }
    return cache[path];
  }

  function table(headers, rows) {
    var thead = el("thead", {}, [el("tr", {}, headers.map(function (h) { return el("th", { text: h }); }))]);
    var tbody = el("tbody", {}, rows.map(function (cells) {
      return el("tr", {}, cells.map(function (c) {
        return el("td", {}, [c instanceof Node ? c : document.createTextNode(c === null || c === undefined ? "" : String(c))]);
      }));
    }));
    return el("div", { class: "table-wrap" }, [el("table", { class: "data" }, [thead, tbody])]);
  }

  function badge(text, kind) {
    return el("span", { class: "badge badge-" + kind, text: text });
  }

  function section(title, children, note) {
    return el("section", { class: "block" }, [el("h3", { text: title })]
      .concat(note ? [el("p", { class: "note", text: note })] : []).concat(children));
  }

  // ---- Views ---------------------------------------------------------------

  function viewStix(entry) {
    var box = el("div", { class: "graph-view" }, [
      el("p", { class: "note" }, ["The STIX 2.1 bundle ", fileLink(entry.stix),
        ", drawn the way the OASIS STIX Visualizer draws it. Relationships and embedded references are the edges. Click the file name to download it."]),
      el("p", { class: "loading", text: "Loading STIX bundle..." })]);
    getJSON(entry.stix).then(function (b) {
      box.lastChild.remove();
      if (typeof vis === "undefined") throw new Error("the graph library did not load");
      StixGraph.mount(box, b);
    }).catch(function (err) { box.lastChild.textContent = "Could not draw the bundle: " + err.message; });
    return box;
  }

  function viewJsonCrack(entry) {
    var box = el("div", { class: "graph-view" }, [
      el("p", { class: "note" }, ["The LOLBin template v2 file ", fileLink(entry.jsoncrack),
        ", laid out the way JSON Crack lays it out. Click the file name to download it."]),
      el("p", { class: "loading", text: "Loading template file..." })]);
    getJSON(entry.jsoncrack).then(function (j) {
      box.lastChild.remove();
      JsonGraph.mount(box, j, { title: entry.jsoncrack });
    }).catch(function (err) { box.lastChild.textContent = "Could not draw the file: " + err.message; });
    return box;
  }

  function viewDetections(d) {
    var det = d.detections;
    var dedicated = det.sigma_rules.filter(function (r) { return r.scope === "dedicated"; });
    var related = det.sigma_rules.filter(function (r) { return r.scope === "related"; });
    function sigmaRows(rules) {
      return rules.map(function (r) {
        return [link(r.url, r.title), r.level || "", r.status || "",
                [r.logsource.product, r.logsource.category || r.logsource.service].filter(Boolean).join(" / "),
                r.matched_on.join(", "), r.attack.join(", ")];
      });
    }
    var headers = ["Rule", "Level", "Status", "Log source", "Matches on", "ATT&CK"];
    var events = [];
    Object.keys(det.event_ids).forEach(function (log) {
      det.event_ids[log].forEach(function (e) {
        events.push([log, e.event_id, e.data_components.join(", "), e.techniques.join(", ")]);
      });
    });
    var out = [
      section("SigmaHQ rules written for " + d.image + " (" + dedicated.length + ")",
        [dedicated.length ? table(headers, sigmaRows(dedicated)) : el("p", { text: "None in SigmaHQ." })],
        "The rule matches " + d.image + " as the process, by original file name, or in its command line, and its title names the binary."),
      section("Windows event IDs from ATT&CK detection strategies (" + events.length + ")",
        [events.length ? table(["Log", "Event ID", "Data component", "Techniques"], events)
                       : el("p", { text: "No Windows event IDs in ATT&CK for these techniques." })]),
      section("ATT&CK detection strategies", [table(["Technique", "Strategy", "Analytics (Windows)"],
        det.attack_detection_strategies.map(function (s) {
          return [s.technique, link(s.url, s.id + " " + s.name),
                  s.analytics.map(function (a) { return a.id; }).join(", ")];
        }))])
    ];
    if (related.length) {
      var details = el("details", {}, [el("summary", { text: "Show " + related.length + " related rules" }),
                                        table(headers, sigmaRows(related))]);
      out.push(section("Related SigmaHQ rules (" + related.length + ")", [details],
        d.image + " is one of several processes, a parent process, or appears in a command line."));
    }
    if (det.other_rules.length) {
      out.push(section("Other detection rules", [el("ul", {}, det.other_rules.map(function (u) {
        return el("li", {}, [link(u)]);
      }))]));
    }
    return el("div", {}, out);
  }

  function viewCommands(d) {
    var rows = d.relationship.associated_commands.map(function (c) {
      return [el("code", { text: c.command }), el("span", { class: "intent", text: c.intent || "" }),
              link(c.source_url, c.source_name || c.source_url)];
    });
    return el("div", {}, [section("Commands from intrusion reports (" + rows.length + ")",
      [rows.length ? table(["Command", "Intent", "Source"], rows) : el("p", { text: "None recorded yet." })],
      "Each command is the exact text of the report it cites. Intent: what the attacker used the command for, " +
      "from that report. IPs and domains are defanged.")]);
  }

  // ATT&CK's own statements about one group, campaign, malware or tool, with the
  // reports they cite, followed by the short evidence tags.
  function evidenceCell(rel, a) {
    var seen = {}, box = el("div", { class: "evidence" });
    (rel.attack_relationships || []).forEach(function (r) {
      if (!r.description || !(a.attack_id ? r.attack_id === a.attack_id : r.source === a.name)) return;
      var text = r.description.replace(/\(Citation:[^)]*\)/g, "").replace(/`/g, "").trim();
      if (!text || seen[text]) return;
      seen[text] = true;
      var p = el("p", { class: "stmt" }, [text]);
      if (r.citations && r.citations.length) {
        p.appendChild(el("span", { class: "cites" }, [" "].concat(r.citations.map(function (c) {
          return link(c.url, "[" + c.source_name + "]");
        }))));
      }
      box.appendChild(p);
    });
    if (a.source) box.appendChild(el("p", { class: "stmt" }, [link(a.source.url, "reported by " + a.source.source_name)]));
    if (a.evidence && a.evidence.length) box.appendChild(el("p", { class: "evi-tags", text: a.evidence.join("; ") }));
    return box;
  }

  function viewIntel(d) {
    var rel = d.relationship;
    function assocTable(items) {
      return table(["Name", "ATT&CK", "Evidence"], items.map(function (a) {
        return [a.name, a.attack_id ? link("https://attack.mitre.org/" + idPath(a.attack_id), a.attack_id) : "not in ATT&CK",
                evidenceCell(rel, a)];
      }));
    }
    var out = [];
    [["Threat groups", rel.associated_apts], ["Campaigns", rel.associated_campaigns],
     ["Malware", rel.associated_malware], ["Tools", rel.associated_tools]].forEach(function (g) {
      if (g[1].length) out.push(section(g[0] + " (" + g[1].length + ")", [assocTable(g[1])]));
    });
    if (rel.technique_only && rel.technique_only.length) {
      out.push(section("Use the technique, binary not named (" + rel.technique_only.length + ")", [el("details", {}, [
        el("summary", { text: "Show " + rel.technique_only.length + " groups, campaigns and malware" }),
        table(["Name", "Type", "ATT&CK", "Evidence"], rel.technique_only.map(function (a) {
          return [a.name, a.type, a.attack_id ? link("https://attack.mitre.org/" + idPath(a.attack_id), a.attack_id) : "",
                  evidenceCell(rel, a)];
        }))])],
        "ATT&CK says these use one of " + d.image + "'s techniques but does not say they used " + d.image +
        " to do it; they may have used another tool or an API. They are kept apart from the associations above."));
    }
    out.push(section("Techniques", [table(["Technique", "Tactics"], d.techniques.map(function (t) {
      return [link(t.url, t.id + " " + t.name), t.tactics.join(", ")];
    }))]));
    if (rel.attack_relationships.length) {
      out.push(section("What ATT&CK says", [el("details", {}, [
        el("summary", { text: "Show " + rel.attack_relationships.length + " ATT&CK statements" }),
        el("ul", { class: "statements" }, rel.attack_relationships.map(function (r) {
          return el("li", {}, [el("b", { text: r.source + ": " }), r.description, " "].concat(
            r.citations.map(function (c) { return link(c.url, "[" + c.source_name + "]"); })));
        }))])]));
    }
    if (d.related_CVE.length) {
      out.push(section("Related CVEs", [table(["CVE", "Description", "Sources"], d.related_CVE.map(function (c) {
        return [link("https://nvd.nist.gov/vuln/detail/" + c.id, c.id), c.description,
                el("span", {}, c.references.map(function (r) { return link(r.url, "[" + r.source_name + "] "); }))];
      }))]));
    }
    return el("div", {}, out);
  }

  function viewMitigations(d) {
    var out = [section("ATT&CK mitigations (" + d.mitigations.length + ")", [table(["Mitigation", "Technique", "Guidance"],
      d.mitigations.map(function (m) {
        return [link("https://attack.mitre.org/mitigations/" + m.id, m.id + " " + m.name), m.technique, m.description];
      }))])];
    if (d.additional_mitigations.length) {
      out.push(section("Additional guidance", [el("ul", {}, d.additional_mitigations.map(function (m) {
        return el("li", { text: m });
      }))]));
    }
    return el("div", {}, out);
  }

  function idPath(id) {
    if (/^G/.test(id)) return "groups/" + id;
    if (/^C/.test(id)) return "campaigns/" + id;
    if (/^S/.test(id)) return "software/" + id;
    if (/^M/.test(id)) return "mitigations/" + id;
    return "techniques/" + id.replace(".", "/");
  }

  // ---- Advanced hunting (KQL) ------------------------------------------------

  var textCache = Object.create(null);
  function getText(path) {
    if (!textCache[path]) {
      textCache[path] = fetch(path).then(function (r) {
        if (!r.ok) throw new Error(path + ": HTTP " + r.status);
        return r.text();
      });
    }
    return textCache[path];
  }

  // A query with Copy and Download buttons.
  function codeBlock(text, path) {
    var status = el("span", { class: "kql-status", role: "status" });
    var copy = el("button", { type: "button", class: "kql-btn", text: "Copy query" });
    copy.addEventListener("click", function () {
      var done = function () { status.textContent = "Copied"; setTimeout(function () { status.textContent = ""; }, 2000); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { status.textContent = "Select the text and copy it"; });
      } else {
        status.textContent = "Select the text and copy it";
      }
    });
    var dl = el("a", { href: path, download: path.split("/").pop(), class: "kql-btn", text: "Download .kql" });
    return el("div", { class: "kql" }, [
      el("div", { class: "kql-bar" }, [copy, dl, status]),
      el("pre", { class: "kql-code", tabindex: "0" }, [el("code", { text: text })])]);
  }

  function renderHunting() {
    var root = document.getElementById("hunting");
    if (!root) return;
    getJSON("lolbins/kql/index.json").then(function (k) {
      root.textContent = "";
      // Only the title shows until it is opened.
      var icon = document.createElement("span");
      icon.className = "hunt-icon";
      icon.setAttribute("aria-hidden", "true");
      // A data table with a magnifying glass: hunting in your own events.
      icon.appendChild(svgFrom('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" ' +
        'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
        '<rect x="2.5" y="3.5" width="14" height="12" rx="1.5"/><path d="M2.5 7.5h14M7.5 7.5v8"/>' +
        '<circle cx="16.5" cy="16.5" r="3.6" fill="var(--surface)"/><path d="M19.1 19.1l2.6 2.6"/></svg>'));
      var outer = el("details", { class: "hunt-outer" }, [
        el("summary", {}, [icon, el("h2", { text: "Advanced hunting (KQL): enrich your events with this data" })])]);
      root.appendChild(outer);
      root = outer;
      root.appendChild(el("p", {}, ["Stream this LOLBin data into your SIEM, such as Microsoft Sentinel, Defender XDR unified platform, " +
        "to correlate events with ATT&CK techniques, threat groups, campaigns, malware, Sigma rules, Windows Event IDs, mitigations, and CVEs."]));
      root.appendChild(el("ol", { class: "hunt-steps" }, [
        el("li", {}, [el("b", { text: "Load the lookup. " }), "externaldata() reads ",
          link(k.csv_url, "lolbins.csv"), " from the public CTI-Driven/LOLBins repository. Each file name has one row."]),
        el("li", {}, [el("b", { text: "Index by name. " }),
          "Each binary has a file name and a PE original file name. A renamed copy still matches. " +
          "For example, rundll32.exe saved as update.exe."]),
        el("li", {}, [el("b", { text: "Join to your table. " }),
          "In DeviceProcessEvents, match FileName and ProcessVersionInfoOriginalFileName. " +
          "In DeviceNetworkEvents, match the InitiatingProcess columns."])]));
      root.appendChild(el("p", { class: "hunt-examples" }, ["The queries and the column list below are examples of how to use this data " +
        "in Microsoft Sentinel or the Microsoft Defender XDR unified platform."]));
      k.queries.forEach(function (q) {
        var det = el("details", {}, [el("summary", { text: q.title }), el("p", { class: "loading", text: "Loading..." })]);
        root.appendChild(det);
        getText(q.file).then(function (t) { det.lastChild.replaceWith(codeBlock(t, q.file)); })
          .catch(function (err) { det.lastChild.textContent = "Could not load: " + err.message; });
      });
      var cols = el("details", {}, [el("summary", { text: "Lookup columns (" + k.columns.length + ")" }),
        table(["Column", "Type", "Content"], k.columns.map(function (c) { return [el("code", { text: c.name }), c.type, c.description]; }))]);
      root.appendChild(cols);
      if (window.location.hash === "#hunting") { root.open = true; root.scrollIntoView(); }
    }).catch(function () { root.hidden = true; });
  }

  // ---- Panels ----------------------------------------------------------------

  var VIEWS = [
    ["stix", "STIX Visualizer", function (e) { return viewStix(e); }],
    ["jsoncrack", "JSON Crack Visualizer", function (e) { return viewJsonCrack(e); }],
    ["intel", "Threat Intel", function (e, d) { return viewIntel(d); }],
    ["commands", "Commands", function (e, d) { return viewCommands(d); }],
    ["detections", "Detections", function (e, d) { return viewDetections(d); }],
    ["mitigations", "Mitigations", function (e, d) { return viewMitigations(d); }]
  ];

  function renderPanel(entry, d) {
    var panel = document.getElementById("panel-template").content.firstElementChild.cloneNode(true);
    panel.id = "panel-" + entry.key;
    panel.querySelector(".binary-name").textContent = d.name;
    var a = panel.querySelector(".attack-link");
    a.href = safeUrl(d.attack.url) || "https://attack.mitre.org/";
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = "ATT&CK " + d.attack.id + " · " + d.attack.name;
    a.title = "Open the ATT&CK " + d.attack.type + " page";
    panel.querySelector(".description").textContent = d.description;
    panel.querySelector(".summary-title").textContent = "An adversary may use " + entry.label + " to:";
    var items = panel.querySelector(".summary-items");
    d.summary.forEach(function (s) { items.appendChild(el("li", { text: s })); });
    var facts = panel.querySelector(".facts");
    var tactics = [];
    d.techniques.forEach(function (t) { t.tactics.forEach(function (x) { if (tactics.indexOf(x) === -1) tactics.push(x); }); });
    [["Paths", d.paths.join("\n"), true], ["Privileges", d.required_privileges.join(", ")],
     ["Capabilities", d.capabilities.join(", ")],
     ["MD5", Object.keys(d.hashes).map(function (k) { return d.hashes[k]; }).join(", "), true],
     ["Techniques", d.techniques.map(function (t) { return t.id + " " + t.name; }).join(", ")],
     ["Tactics", tactics.join(", ")]]
      .forEach(function (f) {
        if (!f[1]) return;
        facts.appendChild(el("dt", { text: f[0] }));
        var dd = el("dd", { class: f[2] ? "mono" : "" });
        f[1].split("\n").forEach(function (line, i) { if (i) dd.appendChild(el("br")); dd.appendChild(document.createTextNode(line)); });
        facts.appendChild(dd);
      });

    var tabs = panel.querySelector(".subtabs");
    var views = panel.querySelector(".views");
    var built = {};
    function show(name) {
      Array.prototype.forEach.call(tabs.children, function (b) {
        b.classList.toggle("active", b.dataset.view === name);
        b.setAttribute("aria-selected", b.dataset.view === name ? "true" : "false");
      });
      Array.prototype.forEach.call(views.children, function (v) { v.hidden = true; });
      if (!built[name]) {
        var spec = VIEWS.filter(function (v) { return v[0] === name; })[0];
        built[name] = el("div", { class: "view view-" + name }, [spec[2](entry, d)]);
        views.appendChild(built[name]);
      }
      built[name].hidden = false;
    }
    VIEWS.forEach(function (v) {
      var b = el("button", { class: "tablinksn", "data-view": v[0], role: "tab", type: "button", text: v[1] });
      b.addEventListener("click", function () { show(v[0]); });
      tabs.appendChild(b);
    });
    show("stix");
    return panel;
  }

  function openBinary(key) {
    var buttons = document.querySelectorAll("#binaries button");
    Array.prototype.forEach.call(buttons, function (b) {
      b.classList.toggle("active", b.dataset.key === key);
      b.setAttribute("aria-selected", b.dataset.key === key ? "true" : "false");
    });
    Array.prototype.forEach.call(document.querySelectorAll("#panels .tabcontent"), function (p) {
      p.hidden = true;
    });
    var existing = document.getElementById("panel-" + key);
    if (existing) {
      existing.hidden = false;
      return;
    }
    var entry = window.LOLBINS.filter(function (e) { return e.key === key; })[0];
    if (!entry) return;
    var loading = el("p", { class: "loading", text: "Loading " + entry.name + "..." });
    document.getElementById("panels").appendChild(loading);
    getJSON(entry.details).then(function (d) {
      loading.remove();
      var panel = renderPanel(entry, d);
      document.getElementById("panels").appendChild(panel);
      panel.hidden = false;
    }).catch(function (err) {
      loading.textContent = "Could not load " + entry.name + ": " + err.message;
    });
  }

  function init(index) {
    window.LOLBINS = index.lolbins;
    renderHunting();
    var stats = document.getElementById("sources");
    stats.textContent = "";
    // Icons, in the order of the labels: a program window, the ATT&CK matrix
    // and the SigmaHQ sigma.
    var STAT_ICONS = [
      '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
      '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/>',
      null
    ];
    // SigmaHQ: its own sigma mark, a cyan sigma on a dark disc.
    var SIGMA_ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="11.5" fill="#202a3d"/>' +
      '<path d="M11.6 8.3H18c-.3 1-1 1.6-2 1.6h-2.6" fill="none" stroke="#29d6ff" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<circle cx="11.2" cy="12.9" r="3.9" fill="none" stroke="#29d6ff" stroke-width="2.3"/></svg>';
    [index.lolbins.length + " binaries", "MITRE ATT&CK v" + index.attack_version, "SigmaHQ"]
      .forEach(function (t, i) {
        var icon = document.createElement("span");
        icon.className = "stat-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.appendChild(svgFrom(STAT_ICONS[i] === null ? SIGMA_ICON :
          '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
          'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + STAT_ICONS[i] + '</svg>'));
        stats.appendChild(el("li", {}, [icon, t]));
      });
    var bar = document.getElementById("binaries");
    document.getElementById("panels").textContent = "";
    index.lolbins.forEach(function (e) {
      var b = el("button", { class: "tablinks", "data-key": e.key, role: "tab", type: "button",
                             title: e.image + " · ATT&CK " + e.attack.id }, [e.label, el("span", { class: "id", text: e.attack.id })]);
      b.addEventListener("click", function () {
        if (window.location.hash === "#" + e.key) openBinary(e.key);
        else window.location.hash = e.key;
      });
      bar.appendChild(b);
    });
    document.getElementById("search").addEventListener("input", function (ev) {
      var q = ev.target.value.trim().toLowerCase();
      Array.prototype.forEach.call(bar.children, function (b) {
        var e = index.lolbins.filter(function (x) { return x.key === b.dataset.key; })[0];
        var hay = (e.label + " " + e.name + " " + e.image + " " + e.attack.id + " " + e.attack.name).toLowerCase();
        b.hidden = !(!q || hay.indexOf(q) !== -1);
      });
      document.getElementById("no-match").hidden = Array.prototype.some.call(bar.children, function (b) { return !b.hidden; });
    });
    function fromHash() {
      var hash = window.location.hash.replace("#", "");
      if (hash === "hunting") {
        var h = document.getElementById("hunting");
        var d = h && h.querySelector(".hunt-outer");
        if (d) d.open = true;
        if (h) h.scrollIntoView({ behavior: "smooth" });
        if (!document.querySelector("#panels .tabcontent")) openBinary(index.lolbins[0].key);
        return;
      }
      openBinary(index.lolbins.some(function (e) { return e.key === hash; }) ? hash : index.lolbins[0].key);
    }
    window.addEventListener("hashchange", fromHash);
    fromHash();
  }

  getJSON("lolbins/index.json").then(init).catch(function (err) {
    document.getElementById("panels").textContent = "Could not load the LOLBin index: " + err.message;
  });
})();
