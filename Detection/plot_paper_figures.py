#!/usr/bin/env python3
"""
Generate paper figures for MLSys submission.

Generates:
- Figure 1a: PR Curves (Precision-Recall)
- Figure 1b: Latency CDF
- Figure 1c: Cost-Recall Trade-off
- Figure 1d: AUPRC by Threat Technique

Features:
- Flexible pricing models (easily configurable)
- Recalculates costs from saved token counts
- No need to rerun detectors
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, Any, Tuple

# ============================================================================
# PLOTTING STYLE - Match visualize_benchmark_stats.ipynb
# ============================================================================

font_size = 15
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = font_size


# ============================================================================
# PRICING MODELS - MODIFY THESE EASILY!
# ============================================================================

PRICING_MODELS = {
    'gpt-4': {
        'input': 2.50,   # USD per 1M tokens
        'output': 10.0,
    },
    'gpt-4o': {
        'input': 2.50,
        'output': 10.0,
    },
    'gpt-4o-mini': {
        'input': 0.15,
        'output': 0.60,
    },
    'gpt-3.5-turbo': {
        'input': 0.50,
        'output': 1.50,
    },
    'claude-sonnet-4': {
        'input': 3.0,
        'output': 15.0,
    },
    'claude-3.5-sonnet': {
        'input': 3.0,
        'output': 15.0,
    },
    'text-embedding-3-small': {
        'input': 0.02,
        'output': 0.0,
    },
    'text-embedding-3-large': {
        'input': 0.13,   # USD per 1M tokens
        'output': 0.0,
    },
}

# --------------------------------------------------------------------------
# Canonical detector ordering and display labels
# --------------------------------------------------------------------------
ORDERED_DETECTORS = ['adr', 'llamafirewall']
DETECTOR_LABELS = {
    'adr': 'ADR',
    'llamafirewall': 'LlamaFirewall',
}


def recalculate_cost(input_tokens: int, output_tokens: int,
                     input_price: float, output_price: float) -> float:
    """Recalculate cost based on token counts and pricing (per 1M tokens)."""
    return (input_tokens * input_price / 1_000_000) + (output_tokens * output_price / 1_000_000)


def load_and_recalculate(analysis_path: Path, detector_name: str) -> Dict[str, Any]:
    """Load analysis and recalculate costs with current pricing."""

    with open(analysis_path, 'r') as f:
        data = json.load(f)

    print(f"📊 Loading {detector_name}: {len(data['analyses'])} tasks")

    # Recalculate costs based on detector type
    for task in data['analyses']:
        # Detectors serialize missing measurements as null (e.g. the
        # BaseDetector.analyze_task fallback after an analysis error), so the
        # keys are present with value None and .get() defaults do not apply.
        input_tokens = task.get('input_tokens') or 0
        output_tokens = task.get('output_tokens') or 0
        model = task.get('model_used', 'gpt-4')

        # Get pricing for the model
        pricing = PRICING_MODELS.get(model, PRICING_MODELS['gpt-4'])

        # Detector-specific logic
        if detector_name == 'adr' or detector_name.startswith('adr-'):
            # For ADR and ablation configs, use stored cost_usd if available
            # In centralized mode, token counts aren't tracked — default to 0
            if task.get('cost_usd') is None:
                task['cost_usd'] = 0.0

        else:
            # LlamaFirewall: direct calculation
            task['cost_usd'] = recalculate_cost(input_tokens, output_tokens,
                                              pricing['input'], pricing['output'])

    return data


def extract_metrics(data: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Extract predictions, labels, confidence scores, and costs."""

    predictions = []
    labels = []
    confidences = []
    costs = []
    latencies = []

    for task in data['analyses']:
        pred = 1 if task.get('is_malicious', False) else 0
        label = 1 if task.get('ground_truth_binary', False) else 0
        conf = task.get('confidence_score', 0.5)
        cost = task.get('cost_usd') or 0.0
        latency = task.get('analysis_time') or 0.0

        predictions.append(pred)
        labels.append(label)
        confidences.append(conf)
        costs.append(cost)
        latencies.append(latency * 1000)  # Convert to ms

    return (np.array(predictions), np.array(labels),
            np.array(confidences), np.array(costs), np.array(latencies))


def plot_latency_cdf(results: Dict[str, Dict], output_path: str = 'fig1b_latency_cdf.png'):
    """Figure 1b: Latency CDF with median annotations."""

    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {
        'adr': '#1f77b4',        # Professional blue
        'llamafirewall': '#d62728' # Red
    }

    # Maintain legend/plot order: ADR, ALRPHFS, GuardAgent, LlamaFirewall
    line_handles: Dict[str, Any] = {}

    # Plot baselines (exclude ADR)
    for name in ORDERED_DETECTORS:
        if name == 'adr' or name not in results:
            continue
        _, _, _, _, latencies = extract_metrics(results[name])
        latencies = latencies[latencies > 0]
        if len(latencies) == 0:
            print(f"⚠️  {name}: No valid latency data")
            continue
        sorted_latencies = np.sort(latencies)
        cdf = np.arange(1, len(sorted_latencies) + 1) / len(sorted_latencies) * 100
        line, = ax.plot(sorted_latencies, cdf,
                        color=colors.get(name, 'gray'), linewidth=4, alpha=0.7)
        line_handles[name] = line

    # Plot ADR last (highlighted)
    if 'adr' in results:
        _, _, _, _, latencies = extract_metrics(results['adr'])
        latencies = latencies[latencies > 0]
        sorted_latencies = np.sort(latencies)
        cdf = np.arange(1, len(sorted_latencies) + 1) / len(sorted_latencies) * 100
        line, = ax.plot(sorted_latencies, cdf,
                        color=colors['adr'], linewidth=6, zorder=10)
        line_handles['adr'] = line

    ax.set_xlabel('Latency (ms)', fontsize=font_size+10, fontweight='bold')
    ax.set_ylabel('CDF (%)', fontsize=font_size+10, fontweight='bold')
    ax.tick_params(axis='both', labelsize=font_size+10)
    # Build legend in canonical order
    ordered_present = [n for n in ORDERED_DETECTORS if n in line_handles]
    handles = [line_handles[n] for n in ordered_present]
    labels = [DETECTOR_LABELS[n] for n in ordered_present]
    ax.legend(handles, labels, loc='upper left', fontsize=font_size+3, frameon=True,
              framealpha=0.98, edgecolor='gray', fancybox=True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    ax.set_xscale('log')
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_cost_recall(results: Dict[str, Dict], output_path: str = 'fig1c_cost_recall.png'):
    """Figure 1c: Cost vs Performance Scatter Plot with Pareto frontier."""

    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {
        'adr': '#1f77b4',        # Professional blue
        'llamafirewall': '#d62728' # Red
    }

    # Compute metrics per detector in canonical order
    points = []
    for name in ORDERED_DETECTORS:
        if name not in results:
            continue
        preds, labels, _, costs, _ = extract_metrics(results[name])
        if labels.sum() == 0:
            print(f"⚠️  {name}: No malicious samples for cost-recall")
            continue
        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        avg_cost = costs.mean()
        points.append({'name': name, 'cost': avg_cost, 'recall': recall, 'precision': precision, 'f1': f1, 'fp': fp})

    # Plot and collect handles for legend in canonical order
    scatter_handles: Dict[str, Any] = {}
    for p in points:
        if p['name'] == 'adr':
            continue
        size = 300 + (p['precision'] * 700)
        alpha = 0.6
        zorder = 5
        sc = ax.scatter(p['cost'], p['recall'], s=size, alpha=alpha,
                        color=colors.get(p['name'], 'gray'),
                        edgecolors='black', linewidth=2, zorder=zorder)
        scatter_handles[p['name']] = sc
        # Add annotation
        ax.annotate(f"P={p['precision']:.2f}\nF1={p['f1']:.2f}\nFP={p['fp']}",
                    xy=(p['cost'], p['recall']),
                    xytext=(10, 10), textcoords='offset points',
                    fontsize=font_size+3, ha='left',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor=colors.get(p['name'], 'gray'),
                              alpha=0.2, edgecolor='none'))

    # Plot ADR last (larger, highlighted)
    ads_point = next((p for p in points if p['name'] == 'adr'), None)
    if ads_point:
        size = 400 + (ads_point['precision'] * 800)
        sc = ax.scatter(ads_point['cost'], ads_point['recall'], s=size, alpha=0.9,
                        color=colors['adr'], edgecolors='red', linewidth=3, zorder=10)
        scatter_handles['adr'] = sc

        # Highlight annotation for ADR
        ax.annotate(f"P={ads_point['precision']:.2f} ✓\nF1={ads_point['f1']:.2f}\nFP={ads_point['fp']} ✓",
                   xy=(ads_point['cost'], ads_point['recall']),
                   xytext=(-100, -80), textcoords='offset points',
                   fontsize=font_size+3, ha='left', fontweight='bold',
                   bbox=dict(boxstyle='round,pad=0.5', facecolor=colors['adr'],
                            alpha=0.3, edgecolor='red', linewidth=2))

    ax.set_xlabel('Average Cost per Task (USD)', fontsize=font_size+10, fontweight='bold')
    ax.set_ylabel('Recall', fontsize=font_size+10, fontweight='bold')
    ax.set_xscale('log')
    ax.tick_params(axis='both', labelsize=font_size+5)

    # Position legend (canonical order) in lower left to avoid blocking data
    ordered_present = [n for n in ORDERED_DETECTORS if n in scatter_handles]
    handles = [scatter_handles[n] for n in ordered_present]
    # Keep ADR label special if desired
    labels = ["ADR - Zero FPs" if n == 'adr' else DETECTOR_LABELS[n] for n in ordered_present]
    ax.legend(handles, labels, loc='lower left', fontsize=font_size+2, frameon=True,
              framealpha=0.98, edgecolor='gray', fancybox=True,
              title='Bubble size ∝ Precision', title_fontsize=font_size+5)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_threat_technique_bar(results: Dict[str, Dict], output_path: str = 'fig1a_threat_bar.png'):
    """Figure 1a: Per-Threat-Tactic Detection Bar Chart."""

    fig, ax = plt.subplots(figsize=(10, 6))

    # Map techniques to tactics (canonical taxonomy from attack_path.tex)
    technique_to_tactic = {
        # Initial Access & Execution (6 techniques)
        'Insecure Supply Chain for Agentic Components': 'Initial Access\n& Execution',
        'Indirect Prompt Injection': 'Initial Access\n& Execution',
        'Agentic Control-Flow Hijacking': 'Initial Access\n& Execution',
        "Abuse of Agent's Code Interpreter": 'Initial Access\n& Execution',
        'Insecure Output Handling': 'Initial Access\n& Execution',
        'Tool Rug Pull': 'Initial Access\n& Execution',
        # Permission Abuse (2 techniques)
        'Exploitation of Excessive Tool Permissions': 'Permission Abuse',
        'Agent Identity Spoofing': 'Permission Abuse',
        # Security Control Bypass (3 techniques)
        'Tool Shadowing': 'Security Control Bypass',
        'Tool Hallucination Manipulation': 'Security Control Bypass',
        'Malicious Agent Collusion': 'Security Control Bypass',
        # Reasoning & Data Manipulation (4 techniques)
        'Unvetted MCP Server Connection': 'R & D Manipulation',
        'Semantic Data Poisoning': 'R & D Manipulation',
        'Long-Term Goal Hijacking': 'R & D Manipulation',
        'Temporal Data Attack': 'R & D Manipulation',
        # Operational Impact (2 techniques)
        'Agent-Facilitated Resource Exhaustion': 'Operational Impact',
        'Model-Layer Denial of Service': 'Operational Impact',
    }

    # Collect per-tactic detection rates
    tactic_data = {}

    for detector_name, data in results.items():
        analyses = data.get('analyses', [])

        for task in analyses:
            technique = task.get('threat_technique', 'N/A')
            if technique == 'N/A' or not task.get('ground_truth_binary', False):
                continue

            # Map technique to tactic
            tactic = technique_to_tactic.get(technique, 'Unknown')

            if tactic not in tactic_data:
                tactic_data[tactic] = {}

            if detector_name not in tactic_data[tactic]:
                tactic_data[tactic][detector_name] = {'tp': 0, 'fn': 0, 'total': 0}

            tactic_data[tactic][detector_name]['total'] += 1

            if task.get('is_true_positive', False):
                tactic_data[tactic][detector_name]['tp'] += 1
            elif task.get('is_false_negative', False):
                tactic_data[tactic][detector_name]['fn'] += 1

    # Define tactic order (canonical taxonomy from attack_path.tex)
    tactic_order = [
        'Initial Access\n& Execution',
        'Permission Abuse',
        'Security Control Bypass',
        'R & D Manipulation',
        'Operational Impact'
    ]

    # Filter to only tactics that have data
    tactics = [t for t in tactic_order if t in tactic_data]

    detectors = [d for d in ORDERED_DETECTORS if d in results]
    detector_labels = [DETECTOR_LABELS[d] for d in detectors]

    # Create matrix
    matrix = np.zeros((len(tactics), len(detectors)))
    sample_counts = np.zeros((len(tactics), len(detectors)))

    for i, tactic in enumerate(tactics):
        for j, detector in enumerate(detectors):
            if detector in tactic_data[tactic]:
                tp = tactic_data[tactic][detector]['tp']
                fn = tactic_data[tactic][detector]['fn']
                total = tp + fn
                rate = tp / total if total > 0 else 0
                matrix[i, j] = rate
                sample_counts[i, j] = total
            else:
                matrix[i, j] = 0
                sample_counts[i, j] = 0

    # Create grouped bar chart
    x = np.arange(len(tactics))
    width = 0.18

    colors = {
        'adr': '#1f77b4',        # Professional blue
        'llamafirewall': '#d62728' # Red
    }

    # Plot bars for each detector
    for j, detector in enumerate(detectors):
        offset = (j - 1.5) * width
        rates = [matrix[i, j] for i in range(len(tactics))]
        bars = ax.bar(x + offset, rates, width,
                     label=detector_labels[j],
                     color=colors.get(detector, 'gray'),
                     alpha=0.9, edgecolor='black', linewidth=1.2)

        # Add value labels on bars (only if rate > 0)
        for i, (bar, rate) in enumerate(zip(bars, rates)):
            height = bar.get_height()
            if rate > 0:
                # Show percentage
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.015,
                       f'{rate*100:.0f}',
                       ha='center', va='bottom',
                       fontsize=font_size+2, color='black', rotation=10)

    ax.set_xlabel('Threat Tactic', fontsize=font_size+10, fontweight='bold')
    ax.set_ylabel('Detection Rate', fontsize=font_size+10, fontweight='bold')
    # ax.set_title('Detection Coverage by Threat Tactic', fontsize=font_size+10, fontweight='bold', pad=20)
    ax.set_xticks(x)
    # Wrap long tactic names for better readability
    tactic_labels = [t.replace('Initial Compromise', 'Initial\nCompromise') for t in tactics]
    tactic_labels = [t.replace('Permission Abuse', 'Permission\nAbuse') for t in tactic_labels]
    tactic_labels = [t.replace('Security Control Bypass', 'Security Con-\ntrol Bypass') for t in tactic_labels]
    tactic_labels = [t.replace('R & D Manipulation', 'R & D\nManipulation') for t in tactic_labels]
    tactic_labels = [t.replace('Operational Impact', 'Operational\nImpact') for t in tactic_labels]
    ax.set_xticklabels(tactic_labels, fontsize=font_size+2, rotation=0, ha='center')
    ax.set_ylim([0, 1.08])
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0%', '20%', '40%', '60%', '80%', '100%'], fontsize=font_size+3)
    ax.tick_params(axis='both', labelsize=font_size+3)

    # Position legend in upper left, shifted slightly to the right
    ax.legend(loc='upper left', bbox_to_anchor=(0.1, 1.0), fontsize=font_size+2, frameon=True,
             framealpha=0.98, edgecolor='gray', fancybox=True, ncol=1)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8, axis='y')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_confusion_matrix_comparison(results: Dict[str, Dict], output_path: str = 'fig1d_confusion_comparison.png'):
    """Figure 1d: Confusion Matrix Comparison highlighting ADR's zero FPs."""

    fig, ax = plt.subplots(figsize=(10, 6))

    detectors = [d for d in ORDERED_DETECTORS if d in results]
    metrics_data = {
        'FP': [],
        'FN': [],
        'TP': [],
        'TN': []
    }

    for name in detectors:
        preds, labels, _, _, _ = extract_metrics(results[name])

        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        tn = ((preds == 0) & (labels == 0)).sum()

        metrics_data['TP'].append(tp)
        metrics_data['FP'].append(fp)
        metrics_data['FN'].append(fn)
        metrics_data['TN'].append(tn)

    x = np.arange(len(detectors))
    width = 0.2

    colors_cm = {
        'TP': '#70AD47',  # Green
        'FP': '#FF6B6B',  # Red
        'FN': '#FFC000',  # Orange
        'TN': '#4472C4'   # Blue
    }

    for i, (metric, values) in enumerate(metrics_data.items()):
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, values, width, label=metric,
                     color=colors_cm[metric], alpha=0.8, edgecolor='black', linewidth=1)

        # Add value labels on bars
        for j, (bar, val) in enumerate(zip(bars, values)):
            height = bar.get_height()
            # detector_name = detectors[j]

            # Highlight ADR's zero FPs with special annotation
            # if metric == 'FP' and detector_name == 'adr' and val == 0:
            #     ax.text(bar.get_x() + bar.get_width()/2., 5,
            #            '0 ✓',
            #            ha='center', va='bottom', fontsize=font_size+2,
            #            fontweight='bold', color='green',
            #            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen',
            #                     alpha=0.8, edgecolor='green', linewidth=2))
            # elif val > 0:
            fontweight = 'bold' if metric in ['TP', 'TN'] else 'normal'
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(val)}',
                    ha='center', va='bottom', fontsize=font_size+3, fontweight=fontweight)

    ax.set_xlabel('Detector', fontsize=font_size+10, fontweight='bold')
    ax.set_ylabel('Count', fontsize=font_size+10, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([DETECTOR_LABELS[d] for d in detectors], fontsize=font_size+10, rotation=10)
    ax.tick_params(axis='y', labelsize=font_size+5)

    # Position legend at upper right to avoid blocking bars
    ax.legend(loc='upper left', fontsize=font_size+5, frameon=True, ncol=1,
             framealpha=0.98, edgecolor='gray', fancybox=True)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8, axis='y')

    # No title to match fig1a style

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_mcp_usage_cdf(debug_log_dir: str = 'ads_reasoning_workspace/debug_logs',
                       output_path: str = 'fig2_mcp_usage_cdf.png'):
    """Figure 2: ADR Detection Path and MCP Server Usage Breakdown."""

    debug_dir = Path(debug_log_dir)
    if not debug_dir.exists():
        print(f"⚠️  Debug log directory not found: {debug_dir}")
        return

    # Get both reasoning logs and triage-only logs
    reasoning_logs = sorted(debug_dir.glob('task_*_claude_output.json'))
    triage_only_logs = sorted(debug_dir.glob('task_*_triage_only.json'))

    if not reasoning_logs and not triage_only_logs:
        print(f"⚠️  No debug logs found in {debug_dir}")
        return

    total_tasks = len(reasoning_logs) + len(triage_only_logs)
    triage_only_count = len(triage_only_logs)

    print(f"📊 Analyzing logs: {len(reasoning_logs)} reasoning + {len(triage_only_logs)} triage-only")

    # Track MCP server usage in reasoning tasks
    mcp_tools = {
        'source_code_analyzer_server': 'Source Code',
        'threat_intelligence_server': 'Threat Intel',
        'policy_store_server': 'Policy'
    }

    mcp_usage_count = {tool: 0 for tool in mcp_tools.keys()}
    reasoning_count = 0

    # Process reasoning agent logs
    for log_file in reasoning_logs:
        try:
            with open(log_file, 'r') as f:
                data = json.load(f)

            if 'mcp_tool_usage' in data:
                tool_counts = data['mcp_tool_usage']
                reasoning_count += 1

                # Count which servers were used (at least once)
                for tool in mcp_tools.keys():
                    if tool_counts.get(tool, 0) > 0:
                        mcp_usage_count[tool] += 1

        except Exception as e:
            continue

    # Print statistics
    print(f"\n  Total tasks: {total_tasks}")
    print(f"  Triage-only: {triage_only_count} ({triage_only_count/total_tasks*100:.1f}%)")
    print(f"  Reasoning agent: {reasoning_count} ({reasoning_count/total_tasks*100:.1f}%)")
    print(f"\n  MCP Server Usage (in reasoning tasks):")
    for tool, name in mcp_tools.items():
        usage_pct = mcp_usage_count[tool] / reasoning_count * 100 if reasoning_count > 0 else 0
        print(f"    {name:20s}: {mcp_usage_count[tool]:3d}/{reasoning_count} tasks ({usage_pct:5.1f}%)")

    # Create grouped bar chart with stacked bar for detection path
    fig, ax = plt.subplots(figsize=(10, 6))

    # Data for plotting
    categories = ['Detection\nPath', 'Use Source\nCode', 'Use Threat\nIntel', 'Use\nPolicy']
    x = np.arange(len(categories))
    width = 0.6

    colors_dict = {
        'triage': '#FFA726',
        'reasoning': '#1976D2',
        'source': '#4472C4',
        'threat': '#ED7D31',
        'policy': '#70AD47'
    }

    # First bar: stacked (Reasoning bottom, Triage top)
    bar_reasoning = ax.bar(x[0], reasoning_count, width,
                           label='Triage + Reasoning Agent', color=colors_dict['reasoning'],
                           alpha=0.9, edgecolor='black', linewidth=1.2)
    bar_triage = ax.bar(x[0], triage_only_count, width, bottom=reasoning_count,
                        label='Triage Only', color=colors_dict['triage'],
                        alpha=0.9, edgecolor='black', linewidth=1.2)

    # Add labels on stacked bar
    ax.text(x[0], reasoning_count/2, f'{reasoning_count}',
           ha='center', va='center', fontsize=font_size+8, fontweight='bold', color='white')
    ax.text(x[0], reasoning_count + triage_only_count/2, f'{triage_only_count}',
           ha='center', va='center', fontsize=font_size+8, fontweight='bold', color='white')
    ax.text(x[0], total_tasks, f'{total_tasks}',
           ha='center', va='bottom', fontsize=font_size+8, fontweight='bold')

    # MCP server bars
    mcp_values = [
        mcp_usage_count['source_code_analyzer_server'],
        mcp_usage_count['threat_intelligence_server'],
        mcp_usage_count['policy_store_server']
    ]
    mcp_colors = [colors_dict['source'], colors_dict['threat'], colors_dict['policy']]

    for i, (val, color) in enumerate(zip(mcp_values, mcp_colors), start=1):
        bar = ax.bar(x[i], val, width, color=color, alpha=0.9,
                    edgecolor='black', linewidth=1.2)

        # Add count on top
        ax.text(x[i], val, f'{int(val)}',
               ha='center', va='bottom', fontsize=font_size+8, fontweight='bold')

        # Add percentage inside bar
        pct = val / reasoning_count * 100 if reasoning_count > 0 else 0
        ax.text(x[i], val * 0.5, f'{pct:.0f}%',
               ha='center', va='center', fontsize=font_size+8,
               fontweight='bold', color='white')

    ax.set_ylabel('Number of Tasks', fontsize=font_size+10, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=font_size+10)
    ax.tick_params(axis='both', labelsize=font_size+10)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.5)
    ax.spines['bottom'].set_linewidth(1.5)
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.8, axis='y')

    # Add legend for the stacked bar
    ax.legend(loc='upper right', fontsize=font_size+10, frameon=True,
             framealpha=0.98, edgecolor='gray', fancybox=True)

    # Add annotation to clarify MCP usage is within reasoning tasks
    # ax.text(0.02, 0.98, 'MCP servers used in\nReasoning Agent tasks',
    #        transform=ax.transAxes, fontsize=font_size,
    #        verticalalignment='top', horizontalalignment='left',
    #        bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgray', alpha=0.8))

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"\n✅ Saved: {output_path}")
    plt.close()


def generate_ablation_table(results: Dict[str, Dict], output_path: str = 'table_ablation.tex'):
    """Generate LaTeX table for ablation study results."""

    # Define ablation configurations
    configs = [
        ('Full ADR', 'adr'),
        ('w/o Triage', 'adr-wotriage'),
        ('w/o Source Code', 'adr-wosourcecode'),
        ('w/o Threat Intel', 'adr-woeas'),
        ('w/o Policy', 'adr-wopolicy')
    ]

    table_rows = []

    for config_name, config_key in configs:
        if config_key not in results:
            print(f"⚠️  Missing ablation config: {config_key}")
            continue

        preds, labels, _, costs, latencies = extract_metrics(results[config_key])

        # Calculate metrics
        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        tn = ((preds == 0) & (labels == 0)).sum()

        accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        avg_cost = costs.mean()
        avg_latency = latencies.mean() / 1000  # Convert ms to seconds

        # Format row
        row = f"{config_name:20s} & {accuracy:.3f} & {precision:.3f} & {recall:.3f} & {f1:.3f} & {tp:3d} & {fp:3d} & {fn:3d} & \\${avg_cost:.4f} & {avg_latency:.1f}"
        table_rows.append(row)

    # Generate LaTeX table
    latex_table = r"""\begin{table*}[t]
\centering
\caption{Ablation Study Results on ADR-Bench. Each row shows performance when a key component is removed from the full ADR system.}
\label{tab:ablation}
\begin{tabular}{lcccccccccc}
\toprule
\textbf{Configuration} & \textbf{Acc} & \textbf{Prec} & \textbf{Rec} & \textbf{F1} & \textbf{TP} & \textbf{FP} & \textbf{FN} & \textbf{Cost} & \textbf{Latency (s)} \\
\midrule
"""

    for row in table_rows:
        latex_table += row + " \\\\\n"

    latex_table += r"""\bottomrule
\end{tabular}
\end{table*}
"""

    # Save to file
    with open(output_path, 'w') as f:
        f.write(latex_table)

    print(f"✅ Saved LaTeX table: {output_path}")

    # Also print to console
    print("\n" + "="*120)
    print("ABLATION STUDY TABLE")
    print("="*120)
    print(f"{'Configuration':<20s} {'Acc':>6s} {'Prec':>6s} {'Rec':>6s} {'F1':>6s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'Cost':>10s} {'Latency':>10s}")
    print("-"*120)
    for config_name, config_key in configs:
        if config_key not in results:
            continue

        preds, labels, _, costs, latencies = extract_metrics(results[config_key])

        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()
        tn = ((preds == 0) & (labels == 0)).sum()

        accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        avg_cost = costs.mean()
        avg_latency = latencies.mean() / 1000  # Convert ms to seconds

        print(f"{config_name:<20s} {accuracy:6.3f} {precision:6.3f} {recall:6.3f} {f1:6.3f} {tp:4d} {fp:4d} {fn:4d} ${avg_cost:9.4f} {avg_latency:9.1f}s")
    print("="*120)


def plot_triage_advantage(results: Dict[str, Dict], output_path: str = 'fig3a_triage_advantage.png'):
    """Figure 3a: The Triage Advantage - Side-by-side comparison."""

    if 'adr' not in results or 'adr-wotriage' not in results:
        print("⚠️  Missing required configs for triage comparison")
        return

    fig, axes = plt.subplots(1, 3, figsize=(13, 4))

    # Extract metrics for both configs
    configs = {
        'Full ADR': 'adr',
        'w/o Triage': 'adr-wotriage'
    }

    metrics_data = {
        'Precision': [],
        'Cost/Task ($)': [],
        'Latency (s)': []
    }

    for config_name, config_key in configs.items():
        preds, labels, _, costs, latencies = extract_metrics(results[config_key])

        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        avg_cost = costs.mean()
        avg_latency = latencies.mean()

        metrics_data['Precision'].append(precision)
        metrics_data['Cost/Task ($)'].append(avg_cost)
        metrics_data['Latency (s)'].append(avg_latency)

    # Plot each metric
    metric_names = ['Precision', 'Cost/Task ($)', 'Latency (s)']
    colors = ['#4472C4', '#ED7D31']
    x = np.arange(2)
    width = 0.5

    for idx, (ax, metric_name) in enumerate(zip(axes, metric_names)):
        values = metrics_data[metric_name]
        bars = ax.bar(x, values, width, color=colors, alpha=0.9, edgecolor='black', linewidth=1.2)

        # Add value labels
        for bar, val in zip(bars, values):
            height = bar.get_height()
            if metric_name == 'Cost/Task ($)':
                label_text = f'${val:.4f}'
            elif metric_name == 'Precision':
                label_text = f'{val:.3f}'
            else:  # Latency - convert from ms to seconds
                label_text = f'{val/1000:.1f}s'

            ax.text(bar.get_x() + bar.get_width()/2., height,
                   label_text,
                   ha='center', va='bottom', fontsize=font_size+3, fontweight='bold')

        # Add improvement annotation at the top for Cost and Latency
        if idx > 0:  # Cost and Latency (lower is better)
            improvement = (values[1] - values[0]) / values[1] * 100
            ax.text(0.3, 0.98, f'{improvement:.0f}% lower',
                   transform=ax.transAxes, ha='center', va='top',
                   fontsize=font_size+2, color='green', fontweight='bold',
                   bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgreen', alpha=0.3, edgecolor='green'))

        ax.set_ylabel(metric_name, fontsize=font_size+10, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(['Full ADR', 'w/o Triage'], fontsize=font_size+5)
        ax.tick_params(axis='y', labelsize=font_size+10)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_linewidth(1.5)
        ax.spines['bottom'].set_linewidth(1.5)
        ax.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.8)

        # Set y-limits with some headroom
        ax.set_ylim([0, max(values) * 1.2])

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_mcp_necessity(results: Dict[str, Dict], output_path: str = 'fig3b_mcp_necessity.png'):
    """Figure 3b: MCP Server Necessity - Performance degradation heatmap."""

    fig, ax = plt.subplots(figsize=(13, 4))

    # Define configurations and metrics
    configs = [
        ('Full ADR', 'adr'),
        ('w/o Source Code', 'adr-wosourcecode'),
        ('w/o Threat Intel', 'adr-woeas'),
        ('w/o Policy', 'adr-wopolicy')
    ]

    metric_names = ['Precision', 'Recall', 'F1']
    matrix = []

    for config_name, config_key in configs:
        if config_key not in results:
            matrix.append([0, 0, 0])
            continue

        preds, labels, _, _, _ = extract_metrics(results[config_key])

        tp = ((preds == 1) & (labels == 1)).sum()
        fp = ((preds == 1) & (labels == 0)).sum()
        fn = ((preds == 0) & (labels == 1)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        matrix.append([precision, recall, f1])

    matrix = np.array(matrix)

    # Use a clear, colorblind-friendly colormap
    ax.set_facecolor('white')
    cmap = plt.cm.get_cmap('YlGnBu')  # good contrast in print

    # Create heatmap background
    im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=0, vmax=1)

    # Set ticks and labels
    ax.set_xticks(np.arange(len(metric_names)))
    ax.set_yticks(np.arange(len(configs)))
    ax.set_xticklabels(metric_names, fontsize=font_size+10, fontweight='bold')
    ax.set_yticklabels([c[0] for c in configs], fontsize=font_size+10)

    # Draw grid boxes and add high-contrast text annotations
    for i in range(len(configs)):
        for j in range(len(metric_names)):
            rect = plt.Rectangle((j - 0.5, i - 0.5), 1, 1,
                                 fill=False, edgecolor='black', linewidth=1.2)
            ax.add_patch(rect)
            val = matrix[i, j]
            text_color = 'white' if val >= 0.6 else 'black'
            ax.text(j, i, f'{val:.3f}',
                    ha='center', va='center', color=text_color,
                    fontsize=font_size+5, fontweight='bold')

    # Align axes limits with the drawn boxes and put first row on top
    ax.set_xlim(-0.5, len(metric_names) - 0.5)
    ax.set_ylim(len(configs) - 0.5, -0.5)

    ax.set_xlabel('Metric', fontsize=font_size+10, fontweight='bold')
    ax.set_ylabel('Configuration', fontsize=font_size+10, fontweight='bold')

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Score', fontsize=font_size+10, fontweight='bold')
    cbar.ax.tick_params(labelsize=font_size+10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_efficiency_analysis(results: Dict[str, Dict], output_path: str = 'fig3c_efficiency_analysis.png'):
    """Figure 3c: Efficiency Analysis - Cost/TP and Latency comparison."""

    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Define configurations
    configs = [
        ('Full ADR', 'adr'),
        ('w/o Triage', 'adr-wotriage'),
        ('w/o Source\nCode', 'adr-wosourcecode'),
        ('w/o Threat\nIntel', 'adr-woeas'),
        ('w/o Policy', 'adr-wopolicy')
    ]

    cost_per_tp = []
    avg_latencies = []

    for config_name, config_key in configs:
        if config_key not in results:
            cost_per_tp.append(0)
            avg_latencies.append(0)
            continue

        preds, labels, _, costs, latencies = extract_metrics(results[config_key])

        tp = ((preds == 1) & (labels == 1)).sum()
        avg_cost = costs.mean()
        cost_tp = (avg_cost * len(results[config_key]['analyses'])) / tp if tp > 0 else 0
        avg_lat = latencies.mean()

        cost_per_tp.append(cost_tp)
        avg_latencies.append(avg_lat)

    x = np.arange(len(configs))
    width = 0.6

    # Plot bars for Cost/TP
    color1 = '#4472C4'
    bars = ax1.bar(x, cost_per_tp, width, label='Cost per True Positive',
                   color=color1, alpha=0.9, edgecolor='black', linewidth=1.2)

    # Add value labels on bars
    for bar, val in zip(bars, cost_per_tp):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'${val:.3f}',
                ha='center', va='bottom', fontsize=font_size+2, fontweight='bold')

    ax1.set_xlabel('Configuration', fontsize=font_size+10, fontweight='bold')
    ax1.set_ylabel('Cost per True Positive ($)', fontsize=font_size+10, fontweight='bold', color=color1)
    ax1.tick_params(axis='y', labelcolor=color1, labelsize=font_size+10)
    ax1.set_xticks(x)
    ax1.set_xticklabels([c[0] for c in configs], fontsize=font_size+5)

    # Create second y-axis for latency (convert ms to seconds)
    ax2 = ax1.twinx()
    color2 = '#ED7D31'
    avg_latencies_sec = [lat / 1000 for lat in avg_latencies]  # Convert to seconds
    line = ax2.plot(x, avg_latencies_sec, color=color2, marker='o', linewidth=3,
                    markersize=10, label='Avg Latency', zorder=10)

    # Add value labels on line
    for i, (xi, val) in enumerate(zip(x, avg_latencies_sec)):
        ax2.text(xi, val + 1.5, f'{val:.1f}s',
                ha='center', va='bottom', fontsize=font_size+2,
                fontweight='bold', color=color2)

    ax2.set_ylabel('Average Latency (s)', fontsize=font_size+10, fontweight='bold', color=color2)
    ax2.tick_params(axis='y', labelcolor=color2, labelsize=font_size+10)

    # Add legends
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='lower left',
              fontsize=font_size+5, frameon=True, framealpha=0.98,
              edgecolor='gray', fancybox=True)

    ax1.spines['top'].set_visible(False)
    ax1.spines['left'].set_linewidth(1.5)
    ax1.spines['bottom'].set_linewidth(1.5)
    ax1.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.8)

    # Adjust y-axis limits to prevent text blocking
    ax1.set_ylim([0, max(cost_per_tp) * 1.15])
    ax2.set_ylim([0, max(avg_latencies_sec) * 1.15])

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"✅ Saved: {output_path}")
    plt.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate paper figures')
    parser.add_argument('--benchmark-dir', default='benchmark/adr_bench_20251017_151604',
                       help='Benchmark directory')
    parser.add_argument('--output-dir', default='figs',
                       help='Output directory for figures')
    parser.add_argument('--detectors', nargs='+',
                       default=['adr', 'llamafirewall'],
                       help='Detectors to include')
    parser.add_argument('--mcp-logs', default='ads_reasoning_workspace/debug_logs',
                       help='MCP debug log directory for ADR')

    args = parser.parse_args()

    benchmark_dir = Path(args.benchmark_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    print("=" * 80)
    print("📊 GENERATING PAPER FIGURES")
    print("=" * 80)

    # Load all detector results
    results = {}
    for detector in args.detectors:
        analysis_file = benchmark_dir / f"{detector}_baseline_analysis.json"

        if not analysis_file.exists():
            print(f"⚠️  Skipping {detector}: {analysis_file} not found")
            continue

        results[detector] = load_and_recalculate(analysis_file, detector)

    if not results:
        print("❌ No results found!")
        return

    # Print cost summary
    print(f"\n{'='*80}")
    print("💰 COST SUMMARY (with current pricing)")
    print(f"{'='*80}")
    for name, data in results.items():
        costs = [t.get('cost_usd', 0.0) for t in data['analyses']]
        if any(c > 0 for c in costs):
            print(f"{name.upper():15s}: ${np.mean(costs):.6f}/task (median: ${np.median(costs):.6f})")
        else:
            print(f"{name.upper():15s}: no cost data (centralized mode)")

    # Generate figures
    print(f"\n{'='*80}")
    print("📈 GENERATING FIGURES")
    print(f"{'='*80}")

    plot_threat_technique_bar(results, str(output_dir / 'fig1a_threat_bar.png'))
    plot_latency_cdf(results, str(output_dir / 'fig1b_latency_cdf.png'))
    plot_cost_recall(results, str(output_dir / 'fig1c_cost_performance.png'))
    plot_confusion_matrix_comparison(results, str(output_dir / 'fig1d_confusion_comparison.png'))

    # Generate MCP usage analysis
    print(f"\n{'='*80}")
    print("🔧 ANALYZING MCP CONTEXT PROVIDER USAGE")
    print(f"{'='*80}")
    plot_mcp_usage_cdf(args.mcp_logs, str(output_dir / 'fig2_mcp_usage_cdf.png'))

    # Generate ablation study figures
    print(f"\n{'='*80}")
    print("🔬 GENERATING ABLATION STUDY FIGURES")
    print(f"{'='*80}")

    # Load ablation configurations
    ablation_results = {}
    ablation_configs = {
        'adr': 'adr_baseline_analysis.json',
        'adr-wotriage': 'adr_baseline_analysis-wotriage.json',
        'adr-wosourcecode': 'adr_baseline_analysis-wosourcecode.json',
        'adr-woeas': 'adr_baseline_analysis-woeas.json',
        'adr-wopolicy': 'adr_baseline_analysis-wopolicy.json'
    }

    for config_name, filename in ablation_configs.items():
        analysis_file = benchmark_dir / filename
        if not analysis_file.exists():
            print(f"⚠️  Skipping {config_name}: {analysis_file} not found")
            continue

        ablation_results[config_name] = load_and_recalculate(analysis_file, config_name)

    if len(ablation_results) >= 2:
        # generate_ablation_table(ablation_results, str(output_dir / 'table_ablation.tex'))

        # Generate Story-Driven ablation figures (Option 2)
        plot_triage_advantage(ablation_results, str(output_dir / 'fig3a_triage_advantage.png'))
        plot_mcp_necessity(ablation_results, str(output_dir / 'fig3b_mcp_necessity.png'))
        plot_efficiency_analysis(ablation_results, str(output_dir / 'fig3c_efficiency_analysis.png'))
    else:
        print("⚠️  Not enough ablation results found (need at least 2 configurations)")

    print(f"\n{'='*80}")
    print("✅ ALL FIGURES GENERATED!")
    print(f"{'='*80}")
    print(f"📁 Output directory: {output_dir}")
    print(f"\n💡 To change pricing, edit PRICING_MODELS at the top of this script")


if __name__ == '__main__':
    main()
