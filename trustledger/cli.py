"""TrustLedger Unified Command-Line Interface."""
import argparse
import json
import os
import subprocess  # nosec B404 - used only for fixed-argv internal selftest
import sys
from pathlib import Path

from trustledger.audit.verifier import verify_hmac_log, verify_log
from trustledger.detect.engine import DetectionPipeline


def cmd_verify_log(args: argparse.Namespace) -> int:
    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"Error: Log file not found at {log_path}", file=sys.stderr)
        return 1

    if getattr(args, "mode", "signed") == "hmac":
        state_dir_val = getattr(args, "state_dir", None) or os.environ.get("TRACK4_STATE_DIR")
        if not state_dir_val:
            print("Error: --state-dir (or TRACK4_STATE_DIR) is required for --mode hmac", file=sys.stderr)
            return 1
        key_dir_val = getattr(args, "key_dir", None) or os.environ.get("TRACK4_KEY_DIR")
        passed, reason, entry = verify_hmac_log(
            log_path,
            state_dir=Path(state_dir_val),
            key_dir=Path(key_dir_val) if key_dir_val else None,
        )
    else:
        if args.pubkey:
            pk = Path(args.pubkey).read_bytes()
        elif args.pubkey_hex:
            pk = bytes.fromhex(args.pubkey_hex)
        else:
            print("Error: Either --pubkey or --pubkey-hex is required in signed mode", file=sys.stderr)
            return 1
        passed, reason, entry = verify_log(log_path, pk)

    if passed:
        print(f"PASS: Log integrity verified successfully: {reason}")
        return 0
    print(f"FAIL: Log verification failed: {reason}", file=sys.stderr)
    if entry:
        print(f"Offending record: {json.dumps(entry, indent=2)}", file=sys.stderr)
    return 2


def cmd_detect(args: argparse.Namespace) -> int:
    events_path = Path(args.events)
    approvals_path = Path(args.approvals)
    out_path = Path(args.out)

    if not events_path.exists():
        print(f"Error: Events file not found at {events_path}", file=sys.stderr)
        return 1
    if not approvals_path.exists():
        print(f"Error: Approvals file not found at {approvals_path}", file=sys.stderr)
        return 1

    pipeline = DetectionPipeline(approvals_path)
    alerts = pipeline.run_file(events_path, output_path=out_path, active_response=args.active_response)

    print(f"Processed events. Emitted {len(alerts)} alerts. Output saved to {out_path}.")
    for a in alerts:
        print(f"[{a.severity.value}] {a.rule_id} ({a.identity}): {a.explanation}")
    return 0


def cmd_selftest_attack(_args: argparse.Namespace) -> int:
    """Execute adversarial self-red-team suite relative to package root and report real per-test results."""
    repo_root = Path(__file__).resolve().parent.parent
    adv_dir = repo_root / "tests" / "adversarial"
    if not adv_dir.is_dir():
        print(f"FAIL: Adversarial test directory not found at {adv_dir}", file=sys.stderr)
        return 1

    print("=====================================================================")
    print("TrustLedger Automated Adversarial Self-Red-Team Suite")
    print("=====================================================================")

    cmd = [sys.executable, "-m", "pytest", str(adv_dir), "-v", "-o", "addopts=", "--tb=short"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60, cwd=str(repo_root))  # nosec B603 - fixed argv

    test_lines = [
        line for line in res.stdout.splitlines()
        if "test_attack_" in line or "test_fuzz_" in line
    ]
    for line in test_lines:
        print(line)

    if res.returncode == 0:
        print("=====================================================================")
        print(f"Self-Test Result: {len(test_lines)}/{len(test_lines)} Adversarial & Fuzz Checks PASSED.")
        print("=====================================================================")
        return 0

    print("FAIL: One or more adversarial tests failed:\n", res.stdout, res.stderr, file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trustledger", description="TrustLedger CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_verify = subparsers.add_parser("verify-log", help="Offline tamper-evident audit log verifier")
    p_verify.add_argument("log_path", help="Path to audit.log file")
    p_verify.add_argument("--mode", choices=["signed", "hmac"], default="signed", help="Verification mode: ML-DSA signed or adapter HMAC")
    p_verify.add_argument("--pubkey", help="Path to raw public key file (signed mode)")
    p_verify.add_argument("--pubkey-hex", help="Hex string of signer public key (signed mode)")
    p_verify.add_argument("--state-dir", help="State directory containing state.json (hmac mode)")
    p_verify.add_argument("--key-dir", help="Private key directory containing .head.json / master.key (hmac mode)")
    p_verify.set_defaults(func=cmd_verify_log)

    p_detect = subparsers.add_parser("detect", help="Behavioral log-based anomaly detector")
    p_detect.add_argument("--events", required=True, help="Path to events CSV or JSONL")
    p_detect.add_argument("--approvals", required=True, help="Path to approvals JSON")
    p_detect.add_argument("--out", default="alerts.json", help="Path to output alerts JSON")
    p_detect.add_argument("--active-response", action="store_true", help="Enable automatic containment")
    p_detect.set_defaults(func=cmd_detect)

    p_attack = subparsers.add_parser("selftest-attack", help="Run adversarial red-team self test")
    p_attack.set_defaults(func=cmd_selftest_attack)

    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return int(args.func(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
