# ADR: Agentic AI Detection and Response

ADR (Agentic AI Detection and Response) is an enterprise security system for AI agents. It helps organizations secure employee-facing agents such as Cursor, Claude Code, and Codex, as well as customer-facing agents such as AI support agents.

ADR is **deployed in production at Uber**, and the accompanying paper was accepted to **MLSys 2026**: [Paper PDF](docs/adr-paper.pdf) · [Slides PDF](docs/adr-mlsys-2026-slides.pdf)

## How ADR secures enterprise AI agents

ADR secures enterprise AI agents through five complementary capabilities: discovering unsanctioned AI tools, observing agent activity, evaluating defenses, detecting threats, and preventing unsafe actions.

1. **ADR Discovery: Find the AI tools present on employee endpoints.** Inventories installed AI applications, CLI agents, IDE extensions, local model runtimes, and MCP servers, and flags unknown surfaces for review.
2. **ADR Observability: Understand what AI agents are doing and why.** In production, ADR captures agent intent, tool use, and execution traces across 7+ AI coding tools on macOS, Linux, and Windows, as well as internal automation and customer-facing support agents.
3. **ADR Benchmark: Test agent security under realistic enterprise conditions.** ADR-Bench includes 300+ tasks, 133 MCP servers, and coverage of all 17 agent attack techniques.
4. **ADR Detection: Detect risky agent behavior efficiently.** Its two-tier architecture combines high-recall triage with deeper agentic reasoning for suspicious sessions.
5. **ADR Prevention: Stop unsafe actions before they cause harm.** This component is not included in the current open-source release. **Stay tuned.**

## Repository layout

This repository contains the open-source **ADR Discovery**, **ADR Sensor**, **ADR-Bench**, and **ADR Detector** described in the paper. The offline **ADR Explorer** engine, which hardens ADR Detection through pre-deployment red teaming, is not included here.

| Path                                               | ADR component              | Description                                                                          |
| -------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------ |
| [Discovery/](Discovery/)                           | ADR Discovery              | Inventory the AI apps, CLI agents, IDE extensions, model runtimes, and MCP servers on an endpoint, and flag unknown surfaces for review |
| [Sensor/](Sensor/)                                 | ADR Observability          | Collect and normalize agent telemetry from Claude Code, Cursor, Codex, opencode, Claude Desktop, and others |
| [Detection/](Detection/)                           | ADR Benchmark + Detection  | Dual-agent detector, 133 MCP servers, 303 benchmark tasks, baselines, figure scripts |
| [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) | Evaluation                 | Step-by-step workflow to reproduce benchmark detection and paper figures             |

## Quick start: ADR Detection

```bash
git clone https://github.com/uber/ADR
cd ADR/Detection
uv sync
export ANTHROPIC_API_KEY="..." OPENAI_API_KEY="..."
```

Default detector is `adr` (ADR dual-agent). For keyless smoke tests, use `--detector llamafirewall` (see [Detection/README.md](Detection/README.md)).

See **[docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md)** for the full evaluation workflow (inflate packed benchmark → run detectors → plot figures).

Component documentation:

- [Discovery/README.md](Discovery/README.md): endpoint inventory, probes, and the fingerprint catalog
- [Sensor/README.md](Sensor/README.md): telemetry collection and unified schema
- [Detection/README.md](Detection/README.md): ADR-Bench, detector baselines, MCP infrastructure

## Citation

```bibtex
@inproceedings{li2026adr,
  title={ADR: An Agentic Detection System for Enterprise Agentic AI Security},
  author={Li, Chenning and Hu, Pan and Xu, Justin and Ozbas, Baris and Liu, Olivia and Van, Caroline and Li, Manxue and Zhou, Wei and Alizadeh, Mohammad and Zhang, Pengyu and Sriramadhesikan, KK and Zhang, Ming},
  booktitle={Proceedings of the Ninth Conference on Machine Learning and Systems},
  year={2026}
}
```

Or use [CITATION.cff](CITATION.cff).

## License

Apache License 2.0. See [LICENSE](LICENSE). `Detection/benchmark/agentdojo/` is vendored third-party code under its own [LICENSE](Detection/benchmark/agentdojo/LICENSE) (MIT).

## Data notice

`Detection/` includes **synthetic** benchmark fixtures (fake credentials, emulated environments, prompt-injection scenarios) for defensive security research only. Details: [docs/OPEN_SOURCE_REVIEW.md](docs/OPEN_SOURCE_REVIEW.md).
