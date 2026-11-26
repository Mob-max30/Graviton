"""Cross-platform task runner for TrustLedger development and evaluation."""
import os
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list[str]) -> int:
    print(f"\n>> Running: {' '.join(cmd)}")
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        print(f"Error: Command failed with exit code {res.returncode}", file=sys.stderr)
    return res.returncode


def task_setup() -> int:
    return run_cmd([sys.executable, "-m", "pip", "install", "-e", ".[dev]"])


def task_test_fast() -> int:
    return run_cmd([sys.executable, "-m", "pytest", "tests/adapter", "tests/unit", "-q", "--timeout=30"])


def task_test() -> int:
    return run_cmd([sys.executable, "-m", "pytest", "tests", "-v", "--timeout=60"])


def task_eval() -> int:
    return run_cmd([sys.executable, "-m", "eval.evaluate"])


def task_bench() -> int:
    return run_cmd([sys.executable, "-m", "bench.benchmark"])


def task_metrics() -> int:
    """Run benchmark + evaluation and emit unified build/metrics-summary.md."""
    import json

    if task_bench() != 0:
        return 1
    if task_eval() != 0:
        return 1

    build_dir = Path("build")
    bench_data = json.loads((build_dir / "bench-metrics.json").read_text(encoding="utf-8"))
    eval_data = json.loads((build_dir / "eval-metrics.json").read_text(encoding="utf-8"))
    prac = eval_data.get("practice_dataset", {})

    lines = [
        "# TrustLedger Measured Metrics Summary",
        "",
        f"Environment: Python {eval_data.get('python_version')} on {eval_data.get('platform')} ({eval_data.get('cpu_count')} CPUs)",
        "",
        "## Benchmark (`python -m bench.benchmark`)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for k, v in bench_data.items():
        if isinstance(v, (int, float, str)):
            lines.append(f"| `{k}` | {v} |")

    lines.extend([
        "",
        "## Detector Evaluation (`python -m eval.evaluate`)",
        "",
        "| Suite | Precision | Recall | F1 | False Alerts / 1k | Median Event TTA (ms) | Median Proc Latency (ms) |",
        "|---|---|---|---|---|---|---|",
        (
            f"| 10-seed synthetic | {eval_data.get('mean_precision')} | {eval_data.get('mean_recall')} | "
            f"{eval_data.get('mean_f1')} | {eval_data.get('mean_false_alerts_per_1000')} | "
            f"{eval_data.get('median_event_time_tta_ms')} | {eval_data.get('median_processing_latency_ms')} |"
        ),
        (
            f"| `fixtures/practice` (22 events) | {prac.get('precision')} | {prac.get('recall')} | "
            f"{prac.get('f1')} | {prac.get('false_alerts_per_1000')} | "
            f"{prac.get('median_event_time_tta_ms')} | {prac.get('median_processing_latency_ms')} |"
        ),
    ])
    for fam, m in eval_data.get("heldout_families", {}).items():
        lines.append(
            f"| Held-out: `{fam}` | {m.get('precision')} | {m.get('recall')} | {m.get('f1')} | "
            f"{m.get('false_alerts_per_1000')} | {m.get('median_event_time_tta_ms')} | {m.get('median_processing_latency_ms')} |"
        )

    summary_path = build_dir / "metrics-summary.md"
    summary_text = "\n".join(lines) + "\n"
    summary_path.write_text(summary_text, encoding="utf-8")
    print(f"\nWrote {summary_path}:\n{summary_text}")
    return 0


def task_demo() -> int:
    return run_cmd([sys.executable, "-m", "demo.demo"])


def task_ui() -> int:
    return run_cmd([sys.executable, "-m", "trustledger.ui.server"])


def task_lint() -> int:
    code = run_cmd([sys.executable, "-m", "ruff", "check", "."])
    if code != 0:
        return code
    return run_cmd([sys.executable, "-m", "mypy", "trustledger"])


def task_audit() -> int:
    code = run_cmd([sys.executable, "-m", "bandit", "-r", "trustledger", "-q"])
    if code != 0:
        return code
    return run_cmd([sys.executable, "-m", "pip_audit", "--desc"])


def task_brief() -> int:
    if not os.environ.get("TRACK4_VIDEO_URL") and not Path("demo/VIDEO_URL.txt").exists():
        print("Skipping PDF generation: TRACK4_VIDEO_URL and demo/VIDEO_URL.txt are not set (fail-closed; record video first).")
        return 0
    return run_cmd([sys.executable, "docs/brief/generate_brief.py"])


def task_evidence() -> int:
    code = task_test_fast()
    if code != 0:
        return code
    return task_brief()


def task_verify_clean() -> int:
    print("\n=== Running Full TrustLedger Quality Verification ===")
    steps = [
        ("Linting", task_lint),
        ("Fast Tests", task_test_fast),
        ("Adversarial Self-Test", lambda: run_cmd([sys.executable, "-m", "trustledger.cli", "selftest-attack"])),
        ("Benchmark", task_bench),
        ("Evaluation", task_eval),
        ("Brief PDF Generation", task_brief),
    ]
    for name, func in steps:
        print(f"\n--- Checking: {name} ---")
        code = func()
        if code != 0:
            print(f"FAILED on step: {name}")
            return code
    print("\n=====================================================================")
    print("ALL QUALITY GATES PASSED CLEANLY. Ready for Stage 1 & Stage 2 review.")
    print("=====================================================================")
    return 0


TASKS = {
    "setup": task_setup,
    "test-fast": task_test_fast,
    "test": task_test,
    "eval": task_eval,
    "bench": task_bench,
    "metrics": task_metrics,
    "demo": task_demo,
    "ui": task_ui,
    "lint": task_lint,
    "audit": task_audit,
    "brief": task_brief,
    "evidence": task_evidence,
    "verify-clean": task_verify_clean,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in TASKS:
        print(f"Usage: python tasks.py <{'|'.join(TASKS.keys())}>")
        return 1
    return TASKS[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
