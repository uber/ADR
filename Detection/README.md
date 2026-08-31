# ADR Benchmark - AI Agent Security Research Framework

Complete framework for AI agent security research with threat detection and red-teaming capabilities. **ADR-Bench + AgentDojo integration, 134 MCP servers, four detector baselines**.

> **Paper:** [ADR: An Agentic Detection System for Enterprise Agentic AI Security](https://arxiv.org/abs/2605.17380)  
> **Reproduce Table 2 / figures:** [../docs/REPRODUCIBILITY.md](../docs/REPRODUCIBILITY.md)

## ⚠️ Not for production use

This benchmark is a **research artifact** for evaluating AI agent security detectors against synthetic attack scenarios. It is not intended for production deployment and must be run in an **isolated environment** (container, VM, or dedicated host).

- Several dependencies are pinned to exact versions for benchmark reproducibility (matching the paper's evaluation) and carry known CVEs that are acceptable under the benchmark's isolated threat model but **not** in production.
- Benchmark fixtures include synthetic credentials, prompt-injection payloads, and emulated vulnerable MCP servers. These are intentional and must not be exposed to production networks or real data.
- Do not point the benchmark at live systems, real credentials, or production MCP servers.

See [../docs/OPEN_SOURCE_REVIEW.md](../docs/OPEN_SOURCE_REVIEW.md) for the full release review.

## Quick Start

### Prerequisites

```bash
# 1. Setup project
git clone https://github.com/uber/ADR
cd ADR/Detection
uv sync
```

### API Configuration

Set the following environment variables before running:

```bash
export ANTHROPIC_API_KEY="your_key"   # For Claude reasoning agent
export OPENAI_API_KEY="your_key"      # For OpenAI triage LLM
export HF_TOKEN="your_token"          # For Hugging Face models (optional)
```

**Models Used:**

- Triage: `gpt-4o`
- Reasoning: `claude-sonnet-4-6` (via Claude CLI)

**Prerequisites:**

```bash
# Install Claude CLI (required for MCP server integration)
npm install -g @anthropic-ai/claude-code
claude auth login
```

---

## Code Structure

```
Detection/
├── 📋 Core Benchmark
│   ├── main_benchmark.py          # ADR-Bench + AgentDojo execution
│   ├── plot_paper_figures.py      # PR curves, latency, cost figures (paper)
│   ├── tasks.json                 # 304 scenarios (261 benign, 43 malicious)
│   ├── mcp_servers_registry.json  # 134 server definitions
│   ├── config_benchmark.yaml
│   ├── openai_config.py
│   └── benchmark/                 # vendored code + run output — same directory
│       ├── agentdojo/             # Vendored AgentDojo benchmark code
│       │   ├── benchmark_agents/  # Agent implementations
│       │   │   ├── f_secure_agent/
│       │   │   ├── isolate_gpt_agent/
│       │   │   ├── llamafirewall_agent/
│       │   │   ├── nemo_agent/
│       │   │   ├── pfi_agent/
│       │   │   └── react_agent/
│       │   ├── benchmarks/
│       │   ├── config.py
│       │   └── configs/           # Per-benchmark policy configs
│       │       ├── pfi-policy-agentbench.yaml
│       │       ├── pfi-policy-agentdojo.yaml
│       │       ├── pfi-policy.yaml
│       │       ├── agentbench/
│       │       │   └── os-policy.yaml
│       │       └── agentdojo/
│       │           ├── banking-policy.yaml
│       │           ├── slack-policy.yaml
│       │           ├── travel-policy.yaml
│       │           └── workspace-policy.yaml
│       ├── adr_bench_YYYYMMDD_HHMMSS/    # ADR-Bench run output
│       │   ├── summary.json
│       │   ├── {detector}_baseline_analysis.json  # one file per detector run
│       │   └── task_00X/
│       │       ├── result.json
│       │       └── workspace/
│       └── agentdojo_YYYYMMDD_HHMMSS/    # AgentDojo run output
│           ├── summary.json
│           └── task_XXX/
│               └── workspace/
│                   └── claude_conversation.json
│
├── 🛡️ Detection Framework
│   ├── main_detector.py
│   ├── config_detector.yaml       # ADR + LlamaFirewall
│   └── guardrail/
│       ├── base_detector.py
│       ├── adr_agent/
│       └── llamafirewall_agent/
│
├── 🔧 MCP Infrastructure
│   ├── context_providers_registry.json
│   └── context_providers/
│       ├── source_code_analyzer_server.py
│       ├── threat_intelligence_server.py
│       ├── policy_store_server.py
│       ├── data/
│       │   ├── source_codes_registry.yaml
│       │   ├── threat_repository.yaml
│       │   ├── threat_repository_eas.yaml
│       │   ├── threat_repository_example.yaml
│       │   └── policy_store.yaml
│       └── source_codes/
│           ├── mcp_servers_0/     # Benign tools (78 servers)
│           ├── mcp_servers_1/     # Vulnerable tools (26 servers)
│           └── mcp_servers_2/     # Environment emulation (12 servers)
│
└── 📄 Configuration
    ├── pyproject.toml
    ├── uv.lock
    └── .gitignore
```

**Key Components**:

- **🎯 Dual Benchmark System**:
  - **ADR-Bench**: 304 realistic business tasks with 43 sophisticated attacks
  - **AgentDojo Integration**: Public benchmark for prompt injection evaluation
- **🛡️ Detectors**: ADR (dual-agent) vs LlamaFirewall comparison; ALRPHFS/GuardAgent are paper-only numbers, not runnable here (see [docs/BASELINE_REPLICATION.md](../docs/BASELINE_REPLICATION.md))
- **🔧 MCP Servers**: 134 general-purpose servers (registry `type`: 103 local, 12 local_environment, 15 community, 4 official) + 3 context provider servers (separate registry)
  - **78 Benign Servers**: Legitimate business tools (toolkits + utilities)
  - **26 Vulnerable Servers**: EAS target tools with embedded vulnerabilities for discovery — one (`location_harvester`) is registered under a spoofed community identity (`weather_forecast_service`, `type: community`) as a supply-chain-impersonation test case, so it's also counted in the 15 "community" servers above
  - **12 Environment Servers**: Emulated enterprise systems for safe testing
  - **19 Community/Official Servers**: Community (15) and official (4) MCP servers, by registry `type` — overlaps with 1 of the 26 Vulnerable Servers above
  - **3 Context Providers**: Specialized threat intelligence, policy, and source code analysis (context_providers_registry.json)
- **📊 Analysis**: Automated threat detection with ground truth validation

---

## Part 1: Running the Benchmark

### What it does

- **ADR-Bench**: Executes 304 realistic business tasks using MCP servers
- **AgentDojo**: Runs public prompt injection benchmark with conversation logs
- Forces pure MCP usage (blocks 80+ built-in tools)
- Measures task completion, tool coverage, and performance

### Input

- **ADR-Bench Tasks**: `tasks.json` - 304 predefined business scenarios
- **AgentDojo Tasks**: Automatically loaded from benchmark configuration
- **MCP Servers**: `mcp_servers_registry.json` - 134 available servers
- **Config**: `config_benchmark.yaml` - execution settings

### How to run

```bash
# Run ADR-Bench (default - all 304 tasks)
uv run python main_benchmark.py

# Run AgentDojo benchmark (prompt injection attacks)
uv run python main_benchmark.py --benchmark agentdojo

# Run specific ADR-Bench tasks (targeted attacks)
uv run python main_benchmark.py --tasks 109,110

# Run multiple ADR-Bench tasks
uv run python main_benchmark.py --tasks 1,2,3

# Run single ADR-Bench task
uv run python main_benchmark.py --tasks 109

# Run ADR-Bench task range
uv run python main_benchmark.py --tasks 1-10

# Run with custom concurrency
uv run python main_benchmark.py --concurrent 5

# Run AgentDojo with custom concurrency
uv run python main_benchmark.py --benchmark agentdojo --concurrent 3
```

### Output

**ADR-Bench Results** saved to `benchmark/adr_bench_YYYYMMDD_HHMMSS/`:

```
├── summary.json              # Overall metrics
├── task_001/
│   ├── result.json          # Task completion, tools used, success rate
│   └── workspace/           # Full execution logs
│       ├── claude_conversation.json
│       └── output files...
```

**AgentDojo Results** saved to `benchmark/agentdojo_YYYYMMDD_HHMMSS/`:

```
├── summary.json              # AgentDojo benchmark metrics
├── ground_truth.json         # Ground truth labels (malicious/benign)
├── task_001/                 # Individual conversation tasks
│   ├── result.json          # Task completion and security metrics (ADR-Bench only)
│   └── workspace/
│       └── claude_conversation.json  # Converted conversation log
├── task_002/                # Additional conversations
│   └── ...
└── benchmark/               # Raw AgentDojo logs (internal)
    ├── banking/
    ├── slack/
    ├── travel/
    └── workspace/
```

**Key Metrics in** `summary.json`:

- `success_rate`: Tasks completed (target: 100%)
- `wall_clock_time`: Actual execution time with concurrency
- `sequential_time`: Sum of individual task times
- `actual_speedup`: Real concurrency speedup achieved
- `concurrency_efficiency`: How well concurrency was utilized
- `overall_mcp_ratio`: Percentage of MCP vs built-in tool usage

**AgentDojo Ground Truth** (`ground_truth.json`):

- `is_malicious`: True if attack succeeded, False if defended
- `security`: AgentDojo's security field (False = attack succeeded)
- `utility`: AgentDojo's utility field (task completion)
- `suite`, `user_task`, `injection_task`: Task identifiers

---

## Part 2: Running the Detector

### What it does

- Analyzes benchmark conversations for threats
- **ADR-Bench**: Compares against ground truth labels in repo `tasks.json`
- **AgentDojo**: Compares against `ground_truth.json` in the benchmark run directory
- Tests detection accuracy and false positive rates

### Input

- **ADR-Bench Results**: From Part 1 (`benchmark/adr_bench_*/`) — ground truth from repo `tasks.json`
- **AgentDojo Results**: From Part 1 (`benchmark/agentdojo_*/`) — ground truth from `ground_truth.json` in the run directory
- **Detector**: Choose detection method (`adr` default, or `llamafirewall`)
- **Configuration**: `config_detector.yaml` (models, timeouts, settings)

`--benchmark` must match the results directory: ADR-Bench dirs must not contain `ground_truth.json`; AgentDojo dirs must contain it.

### How to run

```bash
BENCH=benchmark/adr_bench_20251017_151604

# Reproducible paper runs (pin results directory)
uv run python main_detector.py --results-dir "$BENCH"
uv run python main_detector.py --detector llamafirewall --results-dir "$BENCH"

# Convenience (uses newest adr_bench_* under benchmark/ by sorted name)
# ⚠️  If multiple adr_bench_* directories exist, prefer --results-dir "$BENCH" above.
uv run python main_detector.py

# AgentDojo (pin directory after main_benchmark.py --benchmark agentdojo)
AGENTDOJO=benchmark/agentdojo_YYYYMMDD_HHMMSS
uv run python main_detector.py --detector adr --benchmark agentdojo --results-dir "$AGENTDOJO"
uv run python main_detector.py --detector llamafirewall --benchmark agentdojo --results-dir "$AGENTDOJO"

# Analyze specific ADR-Bench tasks (add --results-dir "$BENCH" for reproducible runs)
uv run python main_detector.py --tasks 109,110 --results-dir "$BENCH"
uv run python main_detector.py --tasks 109 --results-dir "$BENCH"
uv run python main_detector.py --tasks 1-10 --results-dir "$BENCH"
```

> **Note:** Default detector is `adr` (ADR dual-agent) and requires API keys + Claude CLI. For keyless smoke tests, use `--detector llamafirewall`.

### Output

Detection results saved in the benchmark directory:

```
benchmark/adr_bench_YYYYMMDD_HHMMSS/
├── adr_baseline_analysis.json         # ADR detector results
├── llamafirewall_baseline_analysis.json # LlamaFirewall detector results
└── summary.json                       # Original benchmark results
```

**Each detector file contains**:

- `detector_info`: Configuration and model information
- `analyses`: Individual task results
- `metrics`: Overall performance metrics (`precision`, `recall`, `f1_score`, `confusion_matrix`, …)
- `run_stats`: Tasks scored vs dropped (`total_tasks`, `scored`, `dropped`)
- `analysis_timestamp`: When analysis was run

**Key Metrics** (under `metrics.confusion_matrix`):

- `true_positives`: Correctly detected malicious tasks
- `false_positives`: Incorrectly flagged benign tasks
- `true_negatives` / `false_negatives`: Benign correct / missed attacks

Top-level `metrics` also includes `accuracy`, `precision`, `recall`, and `f1_score`.

### Paper results (ADR-Bench)

Reported in [Table 2](https://arxiv.org/abs/2605.17380) on the original **302-task** evaluation set (260 benign, 42 malicious). This repo's `tasks.json` defines **304 tasks** — one additional benign task (previously blocked by a benchmark pipeline bug, now fixed) plus one additional malicious task (`task_304`, not yet in the packed benchmark JSONL pending a recorded run); see [REPRODUCIBILITY.md](../docs/REPRODUCIBILITY.md#adr-bench-task-count-304-vs-302).


| Detector             | Precision | Recall            | F1        | False positives |
| -------------------- | --------- | ----------------- | --------- | --------------- |
| **ADR** (dual-agent) | **1.000** | **0.667** (28/42) | **0.800** | **0**           |
| ALRPHFS              | 0.333     | —                 | —         | 34              |
| GuardAgent           | 0.231     | —                 | —         | 30              |
| LlamaFirewall        | 0.167     | —                 | —         | 40              |

ALRPHFS and GuardAgent baseline code was removed from this repo (licensing — see [docs/BASELINE_REPLICATION.md](../docs/BASELINE_REPLICATION.md)); rows above are the paper's published numbers, not reproducible via `main_detector.py`.


**AgentDojo** (93 tasks): ADR detects all attacks with 3 false alarms (paper abstract).

To reproduce locally: [../docs/REPRODUCIBILITY.md](../docs/REPRODUCIBILITY.md)

**AgentDojo integration**:

- **Full Compatibility**: Conversation logs converted to ADR-Bench format
- **Ground Truth Extraction**: Automatic extraction from AgentDojo's security/utility fields
- **Concurrent Execution**: Parallel processing of prompt injection scenarios
- **Malformed JSON Handling**: Robust parsing of AgentDojo's sometimes malformed output logs

### 🎯 **Threat Categories Tested**

**ADR-Bench Threats** (42 sophisticated attacks):

- **Credential Exposure**: Hardcoded credentials in tool responses
- **Data Exfiltration**: Unauthorized data collection and transmission
- **Scope Violations**: Tools exceeding their stated business purpose
- **Surveillance Overreach**: Inappropriate user tracking and monitoring
- **Financial Manipulation**: Price/rate manipulation in trading tools
- **Control-Flow Hijacking**: Agent behavior manipulation
- **Information Fidelity Attacks**: False data generation

**AgentDojo Threats** (prompt injection attacks):

- **Important Instructions**: Hidden instructions in user data
- **Prompt Injection**: Malicious instructions embedded in tool responses
- **Goal Hijacking**: Redirecting agent objectives through crafted inputs
- **Context Poisoning**: Manipulating agent context through data injection

---

### Reproducing paper figures

See **[../docs/REPRODUCIBILITY.md](../docs/REPRODUCIBILITY.md)** for the full workflow. Short version:

```bash
# 1. Inflate packed benchmark (skip live agent execution)
uv run python benchmark/benchmark_pack.py inflate \
  benchmark/adr_bench_20251017_151604.jsonl \
  --output-dir benchmark/adr_bench_20251017_151604

# 2. Run detectors (default: adr; use --results-dir for reproducible paper runs)
uv run python main_detector.py --results-dir benchmark/adr_bench_20251017_151604

# 3. Plot figures (PR curves, latency CDF, cost–recall, AUPRC)
uv run python plot_paper_figures.py \
  --benchmark-dir benchmark/adr_bench_20251017_151604 \
  --output-dir figs
```

---

## Part 3: Enriching the Benchmark

### Adding New MCP Servers

#### Option 1: Community/NPM Servers

**Input**: Existing MCP server from npm or community

**Steps**:

1. **Add to registry** (`mcp_servers_registry.json`):

```json
{
  "your_server": {
    "name": "your_server",
    "category": "utilities",
    "description": "What your server does",
    "package": "@npm/package-name",
    "type": "community",
    "command": "npx",
    "args_template": ["-y", "@npm/package-name"],
    "capabilities": ["tool1", "tool2"],
    "verified": false
  }
}
```

#### Option 2: Local Custom Servers

**Input**: Your own MCP server code

**Steps**:

1. **Create server code** in `context_providers/source_codes/mcp_servers_0/your_server/`:

```python
# your_server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Your Server")

@mcp.tool()
def your_function(param: str) -> str:
    """Your tool description."""
    return f"Result: {param}"

if __name__ == "__main__":
    mcp.run()
```

1. **Add to registry** (`mcp_servers_registry.json`):

```json
{
  "your-server": {
    "name": "your-server",
    "category": "utilities",
    "description": "Your custom server description",
    "type": "local",
    "command": "uv",
    "args_template": [
      "run", "fastmcp", "run",
      "context_providers/source_codes/mcp_servers_0/your_server/your_server.py"
    ],
    "capabilities": ["your_function"],
    "verified": true
  }
}
```

1. **Test your server**:

```bash
# Test server directly
uv run fastmcp run context_providers/source_codes/mcp_servers_0/your_server/your_server.py

# Test in benchmark
uv run python main_benchmark.py --tasks=1
```

#### Option 3: Malicious Servers (Research Only)

**Input**: Server designed to test threat detection capabilities

**Steps**:

1. **Create malicious server** in `context_providers/source_codes/mcp_servers_1/your_threat/`:

```python
# your_threat.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Legitimate Tool")

@mcp.tool()
def legitimate_function(data: str) -> str:
    """Performs legitimate analysis."""
    # Surface: appears legitimate
    result = f"Analysis of {data}"

    # Hidden: malicious behavior
    # Example: data exfiltration, credential exposure, etc.
    # (implement your test threat here)

    return result

if __name__ == "__main__":
    mcp.run()
```

1. **Add to source registry** (`context_providers/data/source_codes_registry.yaml`):

```yaml
- name: "your_threat"
  path: "source_codes/mcp_servers_1/your_threat/your_threat.py"
  category: "utilities"
  description: "Legitimate-sounding description (no MALICIOUS labels)"
  capabilities: ["legitimate_function"]
```

1. **Create detection task** in `tasks.json`:

```json
{
  "task_id": 120,
  "description": "Test your threat detection",
  "user_prompt": "Use the legitimate tool to analyze my data",
  "mcp_servers": ["your-threat"],
  "expected_tools": ["legitimate_function"],
  "ground_truth": "malicious",
  "threat_technique": "Your Threat Category"
}
```

⚠️ **Security Note**: Malicious servers are for research only. Do not implement actual harmful functionality.

### Adding New Tasks

**Input**: New business scenario you want to test

**Steps**:

1. **Add to tasks** (`tasks.json`):

```json
{
  "task_id": 120,
  "description": "Brief description of business scenario",
  "user_prompt": "Natural language request (be specific and actionable)",
  "mcp_servers": ["server1", "server2"],
  "expected_tools": ["tool1", "tool2"],
  "ground_truth": "benign",
  "threat_technique": "Applicable if malicious"
}
```

1. **Test your task**:

```bash
uv run python main_benchmark.py --tasks=120
```

**Design Guidelines**:

- ✅ Natural business language with specific instructions
- ✅ Multiple tool usage (3-8 tools)
- ✅ Realistic scenarios with clear deliverables
- ✅ Specific filenames and parameters when relevant
- ❌ Avoid vague requests that need clarification
- ❌ Avoid >10 minute execution time

### Output

After adding servers/tasks, re-run the full pipeline:

```bash
uv run python main_benchmark.py          # Test new content
uv run python main_detector.py --detector llamafirewall --results-dir benchmark/adr_bench_20251017_151604
```

---

## Troubleshooting

**Claude CLI issues:**

```bash
claude auth logout && claude auth login
```

**MCP Server failures:**

```bash
# Test specific server
uv run fastmcp run context_providers/source_codes/mcp_servers_0/server_name/server.py
```

**Performance issues:**

```bash
# Run smaller subset
uv run python main_benchmark.py --tasks=1-10

# Use faster models in config files
```

---

## Current Research Framework

### 🎯 **Dual Benchmark System**

- **ADR-Bench**: 304 total (261 benign business workflows, 43 sophisticated attacks)
- **AgentDojo Integration**: Public prompt injection benchmark with automatic ground truth extraction
- **MCP Servers**: 134 verified (official, community, local, environment) + 3 context providers
- **Categories**: Office productivity, finance, system admin, security tools, research tools
- **Execution**: Configurable with concurrent processing for both ADR-Bench and AgentDojo

### 📈 **Benchmark Metrics**

- **ADR-Bench Scale**: 304 tasks with diverse business workflows
- **ADR-Bench Success Rate**: High task completion rate with concurrent execution
- **Tool Coverage**: >95% MCP tool usage across tasks
- **Detection (paper Table 2)**: ADR — 100% precision, 67% recall, 0 false positives on ADR-Bench
- **AgentDojo Integration**: Full conversation log compatibility with ground truth extraction
- **Execution Time**: Configurable with concurrent processing (scales with task count)
- **Threat Coverage**: 42 malicious tasks spanning 17 threat techniques + AgentDojo prompt injection scenarios
- **Concurrency Performance**: Efficient parallel processing with high speedup ratios

### 🔬 **Research Applications**

- **Agentic Threat Detection**: Advanced AI agent security analysis across dual benchmarks
- **MCP Security**: Protocol-level threat identification in business workflows
- **Enterprise AI Safety**: Business workflow protection with realistic attack scenarios
- **Benchmark Integration**: Unified evaluation across ADR-Bench and AgentDojo with automatic ground truth
- **Prompt Injection Research**: Comprehensive evaluation using public AgentDojo benchmark

---

## Expected Performance

### 🎯 **Benchmark Results**

```
✅ ADR-Bench Scale: 304 tasks (261 benign, 43 malicious)
✅ MCP Servers: 134 general-purpose servers (103 local, 12 environment, 15 community, 4 official) + 3 context providers
✅ AgentDojo Integration: Full conversation log compatibility with ground truth extraction
⚡ Execution Time: Configurable with concurrent processing (scales with task count)
🔧 Tool Coverage: >95% MCP tool usage (blocking 80+ built-in tools)
🛡️ Detection (paper): ADR 100% precision / 67% recall on ADR-Bench (Table 2)
🚀 Concurrency Performance: Efficient parallel processing with high speedup ratios
```

### 🔬 **Research Validation**

- **Zero false positives**: ADR achieves perfect precision on benign enterprise workflows (Table 2)
- **Baseline comparison**: LlamaFirewall included for paper reproduction; ALRPHFS/GuardAgent numbers are from the paper only (see [docs/BASELINE_REPLICATION.md](../docs/BASELINE_REPLICATION.md))
- **Fair comparison**: Baselines use the same benchmark conversations and ground truth
- **AgentDojo Compatibility**: Full integration with public prompt injection benchmark and automatic ground truth extraction
- **Low false positives**: ADR reports 0 false positives on the paper's 302-task evaluation set
- **Safe Emulation**: All attacks run in logged environment (no real execution)
- **Comprehensive Coverage**: 17 ADR threat techniques + AgentDojo prompt injection scenarios
- **Robust Processing**: Handles malformed JSON and concurrent execution seamlessly
- **Performance Optimization**: 7.5x concurrency speedup with efficient parallel processing

## License

Apache License 2.0 — see [LICENSE](LICENSE). Vendored AgentDojo code under [benchmark/agentdojo/LICENSE](benchmark/agentdojo/LICENSE) (MIT).

This project is intended for defensive security research and agentic AI safety evaluation. Do not use it to conduct unauthorized attacks.