"""Tests for plot_paper_figures.py input handling."""

import json

import pytest

matplotlib = pytest.importorskip("matplotlib")
matplotlib.use("Agg")

import plot_paper_figures  # noqa: E402

SCORED = {
    "task_id": "task_001",
    "is_malicious": True,
    "ground_truth_binary": True,
    "confidence_score": 0.9,
    "model_used": "gpt-4o-mini",
    "analysis_time": 1.5,
    "input_tokens": 1_000_000,
    "output_tokens": 0,
    "cost_usd": 0.15,
}

# Shape written by BaseDetector.analyze_task's error fallback: the keys are
# present but the measurements are null.
ERRORED = {
    "task_id": "task_002",
    "is_malicious": False,
    "ground_truth_binary": False,
    "confidence_score": 0.0,
    "model_used": None,
    "analysis_time": None,
    "input_tokens": None,
    "output_tokens": None,
    "cost_usd": None,
}


def _write(tmp_path, name, analyses):
    path = tmp_path / f"{name}_baseline_analysis.json"
    path.write_text(json.dumps({"analyses": analyses}))
    return path


@pytest.mark.parametrize("detector", ["llamafirewall", "adr"])
def test_null_measurements_do_not_crash(tmp_path, detector):
    data = plot_paper_figures.load_and_recalculate(
        _write(tmp_path, detector, [dict(SCORED), dict(ERRORED)]), detector
    )

    preds, labels, _, costs, latencies = plot_paper_figures.extract_metrics(data)

    assert preds.tolist() == [1, 0]
    assert labels.tolist() == [1, 0]
    assert costs[1] == 0.0
    assert latencies.tolist() == [1500.0, 0.0]


def test_llamafirewall_cost_recalculated_from_tokens(tmp_path):
    data = plot_paper_figures.load_and_recalculate(
        _write(tmp_path, "llamafirewall", [dict(SCORED)]), "llamafirewall"
    )

    assert data["analyses"][0]["cost_usd"] == pytest.approx(0.15)
