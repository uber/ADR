"""The scorecard: one page per run.

The aggregate number is for tracking. The individual rows are what somebody
fixes, so every false positive and every false negative is listed by manifest
id with the evidence the collector recorded - because the snapshot names the
probe, the channel and the path that produced each asset, and a reader should
not have to open two JSON files side by side to find that out.

Self-contained by construction: one file, no external assets, no network. A
scorecard that needed a CDN would be unreadable on the isolated host that
produced it.
"""

import html
import json
import os
from typing import Any, Dict, List, Optional

CATEGORY_LABELS = {
    "cli_agent": "AI tools - CLI agents",
    "app": "AI tools - apps & browsers",
    "extension": "AI tools - extensions",
    "model_runtime": "AI tools - model runtimes",
    "channel_variant": "AI tools - install variants",
    "mcp_server": "MCP servers",
    "artifact": "Skills & programmable surface",
    "agent": "Agents",
    "negative_control": "Negative controls",
}

_STYLE = """
:root { color-scheme: light dark;
  --bg:#fbfbfa; --fg:#1a1a19; --muted:#6b6b68; --line:#e3e3e0; --card:#fff;
  --ok:#177245; --bad:#a8200d; --warn:#8a6100; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#151514; --fg:#eeeeec; --muted:#9a9a95; --line:#2e2e2b; --card:#1d1d1b;
  --ok:#5bbd88; --bad:#f08a72; --warn:#d9ab54; } }
* { box-sizing: border-box; }
body { margin:0; padding:2.5rem 1.5rem; background:var(--bg); color:var(--fg);
  font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size:1.6rem; margin:0 0 .25rem; letter-spacing:-.01em; }
h2 { font-size:1.05rem; margin:2.5rem 0 .75rem; letter-spacing:-.01em; }
.sub { color:var(--muted); margin:0 0 2rem; font-size:.9rem; }
.verdict { display:inline-block; padding:.15rem .6rem; border-radius:100px;
  font-size:.8rem; font-weight:600; letter-spacing:.02em; }
.pass { background:color-mix(in srgb, var(--ok) 15%, transparent); color:var(--ok); }
.fail { background:color-mix(in srgb, var(--bad) 15%, transparent); color:var(--bad); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(8rem,1fr)); gap:.75rem; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:.5rem; padding:.85rem 1rem; }
.tile .n { font-size:1.5rem; font-weight:600; font-variant-numeric:tabular-nums; }
.tile .k { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; }
.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-weight:500; font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
td.n, th.n { text-align:right; font-variant-numeric:tabular-nums; }
code { font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted); white-space:pre-wrap; }
.id { font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; font-weight:600; }
.bad { color:var(--bad); } .ok { color:var(--ok); } .warn { color:var(--warn); }
.empty { color:var(--muted); font-style:italic; }
"""


def render(score: Dict[str, Any]) -> str:
    """One HTML page from one ``score.json``."""
    run = score.get("run", {})
    gate = score.get("gate", {})
    parts: List[str] = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>ADR Discovery e2e - %s</title>" % _e(run.get("id") or run.get("os", "")),
        "<style>%s</style></head><body><main>" % _STYLE,
        "<h1>ADR Discovery - end-to-end fidelity</h1>",
        "<p class=\"sub\">%s &middot; image <code>%s</code> &middot; collector <code>%s</code>"
        " &middot; catalog <code>%s</code></p>" % (
            _e(run.get("id", "")), _e(run.get("image", "")), _e(run.get("collector", "")),
            _e(str(run.get("catalog_version", "")))),
        _verdict(gate),
        _totals(score),
        _denominator(score),
        _categories(score),
        _fields(score),
        _rows("Misses - installed, not reported", score.get("misses", []), _miss_row,
              ("id", "name", "category", "expected")),
        _rows("Inventions - reported, not installed", score.get("inventions", []), _invention_row,
              ("attributed to", "name", "kind", "why it is wrong", "evidence")),
        _rows("Duplicates - installed once, reported more than once",
              score.get("duplicates", []), _duplicate_row, ("id", "name", "count", "assets")),
        _rows("Excluded - not in the denominator", score.get("excluded", []), _excluded_row,
              ("id", "name", "reason")),
        _crosscutting(score),
        "</main></body></html>",
    ]
    return "\n".join(parts)


def write(score: Dict[str, Any], run_dir: str, filename: str = "report.html") -> str:
    path = os.path.join(run_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(score))
    return path


# -- sections ----------------------------------------------------------


def _verdict(gate: Dict[str, Any]) -> str:
    if gate.get("passed"):
        return "<p><span class=\"verdict pass\">gate passed</span></p>"
    reasons = ", ".join(_e(reason) for reason in gate.get("reasons", []))
    return "<p><span class=\"verdict fail\">gate failed</span> <span class=\"bad\">%s</span></p>" % reasons


def _totals(score: Dict[str, Any]) -> str:
    totals = score.get("totals", {})
    tiles = [("TP", totals.get("tp"), ""), ("FP", totals.get("fp"), "bad" if totals.get("fp") else ""),
             ("FN", totals.get("fn"), "bad" if totals.get("fn") else ""),
             ("DUP", totals.get("dup"), "bad" if totals.get("dup") else ""),
             ("recall", _ratio(totals.get("recall")), ""),
             ("precision", _ratio(totals.get("precision")), "")]
    cells = "".join("<div class=\"tile\"><div class=\"n %s\">%s</div><div class=\"k\">%s</div></div>"
                    % (klass, _e(str(value)), _e(label)) for label, value, klass in tiles)
    return "<div class=\"grid\">%s</div>" % cells


def _denominator(score: Dict[str, Any]) -> str:
    manifest = score.get("manifest", {})
    baseline = score.get("baseline", {})
    rows = [("applicable", manifest.get("applicable"), ""),
            ("installed", manifest.get("installed"), ""),
            ("unavailable", manifest.get("unavailable"), ""),
            ("failed", manifest.get("failed"), "bad" if manifest.get("failed") else ""),
            ("unimplemented", manifest.get("unimplemented"), "warn" if manifest.get("unimplemented") else ""),
            ("baseline assets", baseline.get("asset_count"),
             "ok" if baseline.get("clean") else "bad")]
    body = "".join("<tr><td>%s</td><td class=\"n %s\">%s</td></tr>" % (_e(k), c, _e(str(v)))
                   for k, v, c in rows)
    return ("<h2>What was in play</h2><div class=\"scroll\"><table>"
            "<tr><th>state</th><th class=\"n\">entries</th></tr>%s</table></div>" % body)


def _categories(score: Dict[str, Any]) -> str:
    head = ("<tr><th>category</th><th class=\"n\">TP</th><th class=\"n\">FP</th>"
            "<th class=\"n\">FN</th><th class=\"n\">DUP</th><th class=\"n\">recall</th>"
            "<th class=\"n\">precision</th></tr>")
    rows = []
    for key, values in score.get("by_category", {}).items():
        rows.append("<tr><td>%s</td><td class=\"n\">%s</td><td class=\"n %s\">%s</td>"
                    "<td class=\"n %s\">%s</td><td class=\"n %s\">%s</td>"
                    "<td class=\"n\">%s</td><td class=\"n\">%s</td></tr>" % (
                        _e(CATEGORY_LABELS.get(key, key)), values.get("tp", 0),
                        "bad" if values.get("fp") else "", values.get("fp", 0),
                        "bad" if values.get("fn") else "", values.get("fn", 0),
                        "bad" if values.get("dup") else "", values.get("dup", 0),
                        _ratio(values.get("recall")), _ratio(values.get("precision"))))
    return "<h2>Per category</h2><div class=\"scroll\"><table>%s%s</table></div>" % (head, "".join(rows))


def _fields(score: Dict[str, Any]) -> str:
    """Per field, never blended: an average hides which fact is wrong."""
    fields = score.get("fields", {})
    if not fields:
        return ""
    rows = []
    for name, tally in fields.items():
        wrong = tally.get("wrong", [])
        detail = ", ".join("%s (%s &rarr; %s)" % (_e(item["id"]), _e(str(item["expected"])),
                                                  _e(str(item["observed"]))) for item in wrong[:6])
        rows.append("<tr><td>%s</td><td class=\"n\">%s</td><td class=\"n\">%s</td>"
                    "<td class=\"n %s\">%s</td><td><code>%s</code></td></tr>" % (
                        _e(name), tally.get("checked"), tally.get("correct"),
                        "bad" if tally.get("accuracy", 1) < 1 else "ok",
                        _ratio(tally.get("accuracy")), detail or "&mdash;"))
    return ("<h2>Field accuracy, over true positives</h2><div class=\"scroll\"><table>"
            "<tr><th>field</th><th class=\"n\">checked</th><th class=\"n\">correct</th>"
            "<th class=\"n\">accuracy</th><th>wrong</th></tr>%s</table></div>" % "".join(rows))


def _rows(title: str, rows: List[Dict[str, Any]], formatter: Any, headers: Any) -> str:
    if not rows:
        return "<h2>%s</h2><p class=\"empty\">none</p>" % _e(title)
    head = "".join("<th>%s</th>" % _e(header) for header in headers)
    body = "".join(formatter(row) for row in rows)
    return ("<h2>%s <span class=\"sub\">(%d)</span></h2><div class=\"scroll\"><table>"
            "<tr>%s</tr>%s</table></div>" % (_e(title), len(rows), head, body))


def _miss_row(row: Dict[str, Any]) -> str:
    return "<tr><td class=\"id bad\">%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
        _e(row.get("id", "")), _e(row.get("name", "")), _e(row.get("category", "")),
        _e(json.dumps(row.get("expected", {}))))


def _invention_row(row: Dict[str, Any]) -> str:
    """``matched_on`` is the diagnostic half of an evidence line.

    ``probe/channel path`` says where the collector looked; ``matched_on`` says
    which rule fired there, which is what turns a false positive into a
    one-line bug report against a specific matcher.
    """
    evidence = "; ".join("%s/%s %s [%s]" % (item.get("probe"), item.get("channel"),
                                            item.get("path"), item.get("matched_on"))
                         for item in row.get("evidence", [])[:3])
    attributed = row.get("attributed_to")
    cell = ("<td class=\"id bad\">%s</td>" % _e(attributed) if attributed
            else "<td class=\"empty\">unattributed</td>")
    return "<tr>%s<td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>" % (
        cell, _e(row.get("name", "")), _e(row.get("kind", "")),
        _e(row.get("why_wrong", "")), _e(evidence))


def _duplicate_row(row: Dict[str, Any]) -> str:
    paths = "; ".join("%s (%s)" % (asset.get("install_path"), asset.get("install_method"))
                      for asset in row.get("assets", []))
    return "<tr><td class=\"id bad\">%s</td><td>%s</td><td class=\"n\">%s</td><td><code>%s</code></td></tr>" % (
        _e(row.get("id", "")), _e(row.get("name", "")), row.get("count", 0), _e(paths))


def _excluded_row(row: Dict[str, Any]) -> str:
    return "<tr><td class=\"id\">%s</td><td>%s</td><td class=\"warn\">%s</td></tr>" % (
        _e(row.get("id", "")), _e(row.get("name", "")), _e(row.get("reason", "")))


def _crosscutting(score: Dict[str, Any]) -> str:
    canaries = score.get("canaries", {})
    errors = score.get("errors", {})
    queue = score.get("review_queue", {})
    rows = [
        ("canaries", "%d planted, %d leaked" % (canaries.get("planted", 0), canaries.get("leaked", 0)),
         "ok" if canaries.get("clean") else "bad"),
        ("errors", "%d recorded, %d unexplained" % (errors.get("count", 0), errors.get("unexplained", 0)),
         "ok" if not errors.get("unexplained") else "bad"),
        ("review queue", "%d of %d expected entries queued, %d items total"
         % (queue.get("queued", 0), queue.get("expected", 0), queue.get("size", 0)),
         "ok" if queue.get("passed") else "bad"),
    ]
    body = "".join("<tr><td>%s</td><td class=\"%s\">%s</td></tr>" % (_e(k), c, _e(v))
                   for k, v, c in rows)
    return ("<h2>Cross-cutting checks</h2><div class=\"scroll\"><table>"
            "<tr><th>check</th><th>result</th></tr>%s</table></div>" % body)


def _ratio(value: Optional[float]) -> str:
    return "&mdash;" if value is None else ("%.4g" % value)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)
