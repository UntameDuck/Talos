"""Security experiment runner (지시서 §7, §9.1, §12).

    python experiments/runners/run_security.py --mode all --runs 1000

8종 공격 x 4개 arm 을 --runs 회 반복하고, raw JSONL 과 security_summary.csv 를 만든다.
정상 요청 성공률(Legitimate Request Success Rate)도 함께 측정한다.

**수치는 이 실행에서만 생성된다.** 사전에 채워진 값은 없다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runners"))
from _common import PLOTS_DIR, RAW_DIR, RESULTS_DIR, ensure_dirs, write_run_metadata  # noqa: E402

from boundattack.attacks import ALL_ATTACKS  # noqa: E402
from boundattack.harness import build_harness  # noqa: E402
from boundattack.legit import run_legit_once  # noqa: E402
from boundattack.recorder import ResultWriter  # noqa: E402
from boundattack.runner import run_matrix  # noqa: E402
from boundattack.scenario import establish_legit_session  # noqa: E402

ARMS = ["S0", "S1", "S2", "S3"]


def measure_legit(runs: int) -> pd.DataFrame:
    rows = []
    for arm in ARMS:
        ok = 0
        total = 0
        for _ in range(runs):
            harness, user, pwd = build_harness()
            try:
                ctx = establish_legit_session(harness, user, pwd, arm)
                for sample in run_legit_once(ctx):
                    total += 1
                    ok += 1 if sample.ok else 0
                ctx.client.close()
            finally:
                harness.cleanup()
        rows.append(
            {
                "mode": arm,
                "metric": "legitimate_request",
                "runs": total,
                "success": ok,
                "blocked": total - ok,
                "success_rate": (ok / total) if total else None,
            }
        )
    return pd.DataFrame(rows)


def summarize_attacks(raw_path: Path) -> pd.DataFrame:
    import json

    records = [json.loads(line) for line in raw_path.read_text().splitlines() if line.strip()]
    df = pd.DataFrame(records)
    df = df[df["error_code"] != "N/A"]  # 적용 불가 조합 제외
    grouped = (
        df.groupby(["arm", "attack"])
        .agg(runs=("attack_succeeded", "size"), success=("attack_succeeded", "sum"))
        .reset_index()
    )
    grouped["blocked"] = grouped["runs"] - grouped["success"]
    grouped["success_rate"] = grouped["success"] / grouped["runs"]
    grouped = grouped.rename(columns={"arm": "mode"})
    return grouped[["mode", "attack", "runs", "success", "blocked", "success_rate"]].sort_values(
        ["attack", "mode"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="BoundAuth security experiment")
    parser.add_argument("--mode", default="all", choices=["all", *ARMS])
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--attacks", nargs="*", default=ALL_ATTACKS)
    args = parser.parse_args()

    ensure_dirs()
    arms = ARMS if args.mode == "all" else [args.mode]

    raw_path = RAW_DIR / "security_raw.jsonl"
    if raw_path.exists():
        raw_path.unlink()
    writer = ResultWriter(raw_path)

    print(f"[security] {len(args.attacks)} attacks x {len(arms)} arms x {args.runs} runs ...")
    run_matrix(attacks=args.attacks, arms=arms, runs=args.runs, writer=writer, on_outcome=None)

    attack_summary = summarize_attacks(raw_path)
    print(f"[security] measuring legitimate request success ({args.runs} runs) ...")
    legit_summary = measure_legit(args.runs)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    attack_csv = RESULTS_DIR / "security_summary.csv"
    attack_summary.to_csv(attack_csv, index=False)
    legit_csv = RESULTS_DIR / "legit_summary.csv"
    legit_summary.to_csv(legit_csv, index=False)

    write_run_metadata(
        {"experiment": "security", "runs": args.runs, "arms": arms, "attacks": args.attacks}
    )

    print("\n=== security_summary.csv ===")
    print(attack_summary.to_string(index=False))
    print("\n=== legit_summary.csv ===")
    print(legit_summary.to_string(index=False))
    print(f"\nwrote: {attack_csv}\n       {legit_csv}\n       {RAW_DIR / 'security_raw.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
