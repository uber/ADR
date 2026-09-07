"""The scorecard.

The aggregate number is for tracking; the individual rows are what somebody
fixes. So every miss and every invention is listed by manifest id with the
evidence the collector recorded, rather than summarized into a percentage
that tells a reader only that something got worse.
"""

from __future__ import annotations

import html
from typing import Iterable, List, Optional

from ..scoring.schema import Gate, to_dict
from ..scoring.score import Score

STYLE = """
:root { color-scheme: light dark; }
body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       margin: 0; padding: 2rem; background: Canvas; color: CanvasText; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.sub { opacity: .7; font-size: .9rem; margin-bottom: 1.5rem; }
.verdict { display: inline-block; padding: .2rem .6rem; border-radius: .4rem;
           font-weight: 600; font-size: .85rem; }
.pass { background: #1a7f37; color: #fff; }
.fail { background: #b62324; color: #fff; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 2rem; font-size: .9rem; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid rgba(128,128,128,.3); }
th { font-weight: 600; opacity: .8; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
.empty { opacity: .6; font-style: italic; }
"""


def render(score: Score, gate: Optional[Gate] = None) -> str:
    """One self-contained page. No assets, because it travels as an artifact."""
    document = to_dict(score)
    parts: List[str] = [
        "<!doctype html>", "<meta charset='utf-8'>",
        f"<title>ADR Discovery — {esc(score.run_id)}</title>",
        f"<style>{STYLE}</style>",
        f"<h1>ADR Discovery scorecard — {esc(score.os)}</h1>",
        f"<div class='sub'>{esc(score.run_id)} · image {esc(score.image)} · "
        f"collector {esc(score.collector)}</div>",
    ]

    if gate is not None:
        label = "PASS" if gate.passed else "FAIL"
        css = "pass" if gate.passed else "fail"
        parts.append(f"<p><span class='verdict {css}'>{label}</span></p>")
        if gate.reasons:
            parts.append(_list("Why it failed", gate.reasons))

    parts.append(_totals(score))
    parts.append(_categories(score))
    parts.append(_fields(score))
    parts.append(_cross_cutting(score, document))
    parts.append(_verdict_table("Misses — installed, never reported", score.misses, "reason"))
    parts.append(_verdict_table("Inventions — reported, never installed", score.inventions, "detail"))
    parts.append(_verdict_table("Duplicates — one install, several assets", score.duplicates, "detail"))
    return "\n".join(parts) + "\n"


def _totals(score: Score) -> str:
    counts = score.totals
    rows = [
        ("true positives", counts.tp), ("false positives", counts.fp),
        ("false negatives", counts.fn), ("duplicates", counts.dup),
        ("recall", _ratio(counts.recall)), ("precision", _ratio(counts.precision)),
    ]
    body = "".join(f"<tr><th>{esc(name)}</th><td class='num'>{esc(value)}</td></tr>"
                   for name, value in rows)
    manifest = score.manifest_counts
    applicable = manifest.get("applicable", "?")
    installed = manifest.get("installed", "?")
    return (f"<h2>Totals</h2><p class='sub'>{esc(installed)} installed of {esc(applicable)} applicable "
            f"· unavailable {esc(manifest.get('unavailable', 0))} "
            f"· failed {esc(manifest.get('failed', 0))}</p>"
            f"<table>{body}</table>")


def _categories(score: Score) -> str:
    if not score.by_category:
        return ""
    head = "<tr><th>category</th><th class='num'>TP</th><th class='num'>FP</th>" \
           "<th class='num'>FN</th><th class='num'>DUP</th>" \
           "<th class='num'>recall</th><th class='num'>precision</th></tr>"
    rows = "".join(
        f"<tr><td>{esc(name)}</td><td class='num'>{c.tp}</td><td class='num'>{c.fp}</td>"
        f"<td class='num'>{c.fn}</td><td class='num'>{c.dup}</td>"
        f"<td class='num'>{_ratio(c.recall)}</td><td class='num'>{_ratio(c.precision)}</td></tr>"
        for name, c in sorted(score.by_category.items()))
    return f"<h2>By category</h2><p class='sub'>Never pooled across OS: the denominators differ.</p>" \
           f"<table>{head}{rows}</table>"


def _fields(score: Score) -> str:
    if not score.fields:
        return ""
    rows = "".join(f"<tr><td><code>{esc(name)}</code></td><td class='num'>{_ratio(value)}</td></tr>"
                   for name, value in sorted(score.fields.items()))
    return "<h2>Field accuracy</h2><p class='sub'>Over true positives only, per field — an average " \
           "would hide a collector that always gets one field wrong.</p>" \
           f"<table>{rows}</table>"


def _cross_cutting(score: Score, document: dict) -> str:
    canaries = document["canaries"]
    leaked = canaries["leaked"]
    errors = score.errors
    rows = [
        ("canaries planted", canaries["planted"]),
        ("canaries leaked", leaked),
        ("baseline assets", score.baseline_assets),
        ("errors", errors.get("count", 0)),
        ("unexplained errors", errors.get("unexplained", 0)),
        ("review queue", {True: "ok", False: "failed", None: "n/a"}[score.review_queue_ok]),
    ]
    body = "".join(f"<tr><th>{esc(n)}</th><td class='num'>{esc(v)}</td></tr>" for n, v in rows)
    return f"<h2>Cross-cutting</h2><table>{body}</table>"


def _verdict_table(title: str, verdicts, detail_label: str) -> str:
    listed = list(verdicts)
    if not listed:
        return f"<h2>{esc(title)}</h2><p class='empty'>None.</p>"
    head = f"<tr><th>id</th><th>category</th><th>{esc(detail_label)}</th><th>assets</th></tr>"
    rows = "".join(
        f"<tr><td><code>{esc(v.entry_id)}</code></td><td>{esc(v.category)}</td>"
        f"<td>{esc(v.detail)}</td><td><code>{esc(', '.join(v.assets))}</code></td></tr>"
        for v in listed)
    return f"<h2>{esc(title)}</h2><table>{head}{rows}</table>"


def _list(title: str, items: Iterable[str]) -> str:
    body = "".join(f"<li>{esc(item)}</li>" for item in items)
    return f"<h2>{esc(title)}</h2><ul>{body}</ul>"


def _ratio(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.4g}"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


__all__ = ["render"]
