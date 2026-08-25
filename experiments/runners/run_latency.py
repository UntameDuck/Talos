"""Latency experiment runner (지시서 §7, §9.2, §12).

    python experiments/runners/run_latency.py --mode all --runs 1000

각 arm 에서 정상 요청을 반복하며 end-to-end latency 를 수집하고 latency_summary.csv 를
만든다.

**중요 (지시서 §34):** S3 의 latency 는 BoundKey **시뮬레이터** 기반이며, 실제
BLE round-trip / Secure Element signing 시간을 포함하지 않는다. 따라서 이 값은 실제
S3 하드웨어 latency 의 하한 추정조차 아니다. 하드웨어 실측이 별도로 필요하다.
run_metadata.json 과 CSV 주석에 이를 명시한다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runners"))
from _common import RAW_DIR, RESULTS_DIR, ensure_dirs, write_run_metadata  # noqa: E402

from boundattack.harness import build_harness  # noqa: E402
from boundattack.legit import run_legit_once  # noqa: E402
from boundattack.scenario import establish_legit_session  # noqa: E402

ARMS = ["S0", "S1", "S2", "S3"]


def _percentile(series: pd.Series, q: float) -> float:
    return float(series.quantile(q)) if len(series) else float("nan")


def main() -> int:
    parser = argparse.ArgumentParser(description="BoundAuth latency experiment")
    parser.add_argument("--mode", default="all", choices=["all", *ARMS])
    parser.add_argument("--runs", type=int, default=100)
    args = parser.parse_args()

    ensure_dirs()
    arms = ARMS if args.mode == "all" else [args.mode]

    raw_rows = []
    for arm in arms:
        print(f"[latency] arm={arm} runs={args.runs} ...")
        for _ in range(args.runs):
            harness, user, pwd = build_harness()
            try:
                ctx = establish_legit_session(harness, user, pwd, arm)
                for sample in run_legit_once(ctx):
                    raw_rows.append(
                        {
                            "mode": sample.arm,
                            "method": sample.method,
                            "path": sample.path,
                            "risk_high": sample.risk_high,
                            "status_code": sample.status_code,
                            "ok": sample.ok,
                            "e2e_ms": sample.e2e_ms,
                        }
                    )
                ctx.client.close()
            finally:
                harness.cleanup()

    raw_df = pd.DataFrame(raw_rows)
    raw_path = RAW_DIR / "latency_raw.jsonl"
    raw_df.to_json(raw_path, orient="records", lines=True)

    # 성공 요청만 latency 집계에 포함한다.
    ok_df = raw_df[raw_df["ok"]]
    summary_rows = []
    for mode, group in ok_df.groupby("mode"):
        series = group["e2e_ms"]
        summary_rows.append(
            {
                "mode": mode,
                "metric": "end_to_end",
                "n": int(len(series)),
                "mean_ms": round(float(series.mean()), 3),
                "median_ms": round(float(series.median()), 3),
                "p95_ms": round(_percentile(series, 0.95), 3),
                "p99_ms": round(_percentile(series, 0.99), 3),
                "std_ms": round(float(series.std(ddof=0)), 3),
            }
        )
    summary = pd.DataFrame(summary_rows).sort_values("mode")

    summary_path = RESULTS_DIR / "latency_summary.csv"
    summary.to_csv(summary_path, index=False)

    write_run_metadata(
        {
            "experiment": "latency",
            "runs": args.runs,
            "arms": arms,
            "s3_measurement": "SIMULATOR - not hardware; BLE/SE latency excluded",
        }
    )

    print("\n=== latency_summary.csv (end-to-end, success only) ===")
    print(summary.to_string(index=False))
    print(f"\nwrote: {summary_path}\n       {raw_path}")
    print(
        "\nNOTE: S3 latency is SIMULATOR-based (no BLE RTT / Secure Element signing). "
        "NOT VERIFIED ON HARDWARE."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
