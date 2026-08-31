# Reproducing Paper Results

This guide covers the evaluation workflow for [ADR (arXiv:2605.17380)](https://arxiv.org/abs/2605.17380) using the artifacts in this repository.

## What is included


| Paper component                    | In this repo?                                          |
| ---------------------------------- | ------------------------------------------------------ |
| ADR Sensor (§3.1)                  | Yes — `Sensor/`                                        |
| ADR Detector (§3.2)                | Yes — `Detection/guardrail/`, `main_detector.py`       |
| ADR Explorer / EAS (§3)            | **No** — offline red-teaming engine not released       |
| ADR-Bench (§4)                     | Yes — `tasks.json`, MCP fixtures, packed conversations |
| Production deployment results (§6) | **No** — enterprise telemetry not included             |


## ADR-Bench task count: 304 vs 302

The paper reports **302 tasks** (260 benign, 42 malicious). `tasks.json` in this repository defines **304 tasks** (261 benign, 43 malicious) — two deltas from the paper set:

- One extra **benign** task, blocked in the original evaluation run by a benchmark pipeline bug. After that bug was fixed, the task completes normally and is included in `tasks.json` and the packed benchmark JSONL.
- One extra **malicious** task (`task_304`, `content_localization_service` — a Tag-Block ASCII-smuggling indirect prompt injection), added to exercise the deterministic Unicode-obfuscation detector. As of this writing it is defined in `tasks.json` but **not yet in the packed `adr_bench_20251017_151604.jsonl`** — it needs a recorded conversation from a live `main_benchmark.py --tasks 304` run before it contributes to any detector metric; until then, `benchmark_pack.py inflate` on the packed JSONL still only produces 303 task directories. Running detection against `tasks.json`'s 304-task definitions without a matching recorded conversation for task 304 will report it dropped (see `run_stats.dropped` in Step 2).

Paper Table 2 numbers were computed on the original 302-task set; re-running on the full task list may differ slightly.

## Prerequisites

```bash
cd Detection
uv sync
```

**API keys** (required for detection):

```bash
export ANTHROPIC_API_KEY="..."   # Claude reasoning agent
export OPENAI_API_KEY="..."      # GPT-4o triage
export HF_TOKEN="..."            # Optional — LlamaFirewall / Hugging Face models
```

Default detector is `adr` (ADR dual-agent). For keyless smoke tests, use `--detector llamafirewall`.

**Claude CLI** (required for ADR reasoning with MCP):

```bash
npm install -g @anthropic-ai/claude-code
claude auth login
```

**Unit tests** (deterministic components, no API keys):

```bash
cd Detection && uv run pytest tests/ -q
cd ../Sensor && uv run pytest -q
```

## Workflow overview

```
tasks.json + MCP fixtures
        │
        ├─ (optional) main_benchmark.py  ──► benchmark/adr_bench_*/
        │
        └─ benchmark_pack inflate JSONL  ──► benchmark/adr_bench_20251017_151604/
                    │
                    ▼
            main_detector.py  ──► *_baseline_analysis.json
                    │
                    ▼
            plot_paper_figures.py  ──► figs/
```

The packed JSONL (`benchmark/adr_bench_20251017_151604.jsonl`, ~10 MB) lets you **skip agent execution** and go straight to detection.

---

## Step 1: Get benchmark conversations

### Option A — Inflate packed benchmark (recommended)

```bash
cd Detection

uv run python benchmark/benchmark_pack.py inflate \
  benchmark/adr_bench_20251017_151604.jsonl \
  --output-dir benchmark/adr_bench_20251017_151604
```

This creates `benchmark/adr_bench_20251017_151604/task_XXX/workspace/claude_conversation.json` for all 303 tasks.

### Option B — Run the benchmark from scratch

Executes live agent sessions against MCP servers (slow, requires Claude CLI):

```bash
cd Detection
uv run python main_benchmark.py
# Output: benchmark/adr_bench_YYYYMMDD_HHMMSS/
```

To pack results for sharing:

```bash
uv run python benchmark/benchmark_pack.py deflate benchmark/adr_bench_YYYYMMDD_HHMMSS
```

---

## Step 2: Run detectors

```bash
cd Detection
BENCH=benchmark/adr_bench_20251017_151604

# ADR (dual-agent: triage + reasoning) — default detector
uv run python main_detector.py --results-dir "$BENCH"

# Baseline (paper Table 2)
uv run python main_detector.py --detector llamafirewall --results-dir "$BENCH"
```

Without `--results-dir`, `main_detector.py` uses the latest `adr_bench_*` directory under `benchmark/` (sorted by name). Prefer `--results-dir` for reproducible paper runs.

`--benchmark` must match the results directory layout: **ADR-Bench** dirs have no `ground_truth.json` (labels come from `tasks.json`); **AgentDojo** dirs require `ground_truth.json`. A mismatch exits with an error.

The summary reports **tasks scored N/M**; dropped tasks (missing conversation or errors) are excluded from metrics and flagged with a warning. Each `*_baseline_analysis.json` also includes a `run_stats` object (`total_tasks`, `scored`, `dropped`).

Outputs are written into the benchmark directory:

```
benchmark/adr_bench_20251017_151604/
├── adr_baseline_analysis.json
└── llamafirewall_baseline_analysis.json
```

**AgentDojo** (paper: 93 tasks, prompt injection):

```bash
# Generate AgentDojo conversations first:
uv run python main_benchmark.py --benchmark agentdojo

# Pin the agentdojo_* directory from benchmark output, then detect:
AGENTDOJO=benchmark/agentdojo_YYYYMMDD_HHMMSS
uv run python main_detector.py --detector adr --benchmark agentdojo --results-dir "$AGENTDOJO"
uv run python main_detector.py --detector llamafirewall --benchmark agentdojo --results-dir "$AGENTDOJO"
```

Without `--results-dir`, `main_detector.py` uses the latest `agentdojo_*` directory under `benchmark/`. Prefer `--results-dir` for reproducible runs.

### Configuration

- Detector settings: `config_detector.yaml` (models, `max_concurrent`, timeouts)
- Default ADR models: `gpt-4o` (triage), `claude-sonnet-4-6` (reasoning via Claude CLI)

### Re-run caveats

- **API quota**: If OpenAI triage hits rate limits, the detector escalates all tasks to reasoning (distorts cost and triage ablations). Ensure quota before full runs.
- **Cost**: Full 303-task ADR detection invokes Claude + MCP for escalated tasks; budget API spend accordingly.
- **Concurrency**: `detection.max_concurrent` in `config_detector.yaml` defaults to `5`.

---

## Step 3: Generate paper figures

Requires analysis JSON files from Step 2.

```bash
cd Detection

uv run python plot_paper_figures.py \
  --benchmark-dir benchmark/adr_bench_20251017_151604 \
  --output-dir figs
```

Generates PR curves, latency CDF, cost–recall trade-off, and AUPRC by threat technique (paper §5 figures).

---

## Paper Table 2 reference (ADR-Bench, 302 tasks)

Reported in the paper on the original 302-task evaluation set:


| Detector      | Precision | Recall        | F1    | False positives (benign) |
| ------------- | --------- | ------------- | ----- | ------------------------ |
| **ADR**       | 1.000     | 0.667 (28/42) | 0.800 | **0**                    |
| ALRPHFS       | 0.333     | —             | —     | 34                       |
| GuardAgent    | 0.231     | —             | —     | 30                       |
| LlamaFirewall | 0.167     | —             | —     | 40                       |


ADR prioritizes **zero false positives** on benign enterprise workflows; recall is 67% on the 42 attack scenarios.

ALRPHFS and GuardAgent baseline code was removed from this repo (licensing — see [BASELINE_REPLICATION.md](BASELINE_REPLICATION.md)); the rows above are the paper's published numbers, not reproducible via `main_detector.py`.

**AgentDojo** (93 tasks): ADR detects all attacks with 3 false alarms (paper abstract).

Your local `*_baseline_analysis.json` metrics are printed at the end of `main_detector.py` and stored under `metrics` (with confusion-matrix counts under `metrics.confusion_matrix`) in each analysis file.

---

## Troubleshooting

```bash
# Claude CLI auth
claude auth logout && claude auth login

# Test a single task (pin results dir for reproducibility)
uv run python main_detector.py --detector adr --tasks 108 --results-dir benchmark/adr_bench_20251017_151604

# Keyless single-task smoke test
uv run python main_detector.py --detector llamafirewall --tasks 108 --results-dir benchmark/adr_bench_20251017_151604

# Smaller benchmark subset
uv run python main_benchmark.py --tasks 1-10
```

See [Detection/README.md](../Detection/README.md) for MCP server debugging and benchmark extension.