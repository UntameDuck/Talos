"""Plot generation (지시서 §13).

security_summary.csv / latency_summary.csv 로부터 그래프를 만든다.
**실제 측정값만 사용한다.** 데이터가 없으면 그래프를 만들지 않는다.

그래프 A: Security Level vs Attack Success Rate (S0->S3)
그래프 B: Security Level vs End-to-End Latency
그래프 D: High-risk unauthorized action success (S0->S3)
그래프 C(S3 latency breakdown)는 실제 BLE/SE 측정이 필요하므로 하드웨어 단계에서 생성.
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runners"))
from _common import PLOTS_DIR, RESULTS_DIR, ensure_dirs  # noqa: E402

ARMS = ["S0", "S1", "S2", "S3"]


def _load(name: str) -> pd.DataFrame | None:
    path = RESULTS_DIR / name
    if not path.exists():
        print(f"[plots] skip: {name} not found (run the experiment first)")
        return None
    return pd.read_csv(path)


def plot_security(df: pd.DataFrame) -> None:
    """그래프 A: 공격별 arm 성공률."""
    pivot = df.pivot_table(index="attack", columns="mode", values="success_rate", aggfunc="mean")
    pivot = pivot.reindex(columns=[a for a in ARMS if a in pivot.columns])
    ax = pivot.plot(kind="bar", figsize=(11, 6))
    ax.set_ylabel("Attack Success Rate")
    ax.set_xlabel("Attack")
    ax.set_title("Graph A - Attack Success Rate by Security Level (measured)")
    ax.set_ylim(0, 1.05)
    ax.legend(title="arm")
    plt.tight_layout()
    out = PLOTS_DIR / "graph_a_security.png"
    plt.savefig(out, dpi=130)
    plt.close()
    print(f"[plots] wrote {out}")


def plot_high_risk(df: pd.DataFrame) -> None:
    """그래프 D: high-risk-abuse 성공률."""
    hr = df[df["attack"] == "high-risk-abuse"].set_index("mode")["success_rate"]
    hr = hr.reindex([a for a in ARMS if a in hr.index])
    ax = hr.plot(kind="bar", color=["#c0392b", "#e67e22", "#e67e22", "#27ae60"], figsize=(7, 5))
    ax.set_ylabel("Unauthorized High-Risk API Success Rate")
    ax.set_title("Graph D - High-Risk Abuse Success by Arm (measured)")
    ax.set_ylim(0, 1.05)
    plt.tight_layout()
    out = PLOTS_DIR / "graph_d_high_risk.png"
    plt.savefig(out, dpi=130)
    plt.close()
    print(f"[plots] wrote {out}")


def plot_latency(df: pd.DataFrame) -> None:
    """그래프 B: arm 별 end-to-end latency (median + p95)."""
    e2e = df[df["metric"] == "end_to_end"].set_index("mode")
    e2e = e2e.reindex([a for a in ARMS if a in e2e.index])
    ax = e2e[["median_ms", "p95_ms"]].plot(kind="bar", figsize=(8, 5))
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Graph B - End-to-End Latency by Arm (measured; S3=simulator)")
    ax.legend(["median", "p95"])
    plt.tight_layout()
    out = PLOTS_DIR / "graph_b_latency.png"
    plt.savefig(out, dpi=130)
    plt.close()
    print(f"[plots] wrote {out}")
    print("[plots] NOTE: S3 latency is simulator-based; NOT VERIFIED ON HARDWARE.")


def main() -> int:
    ensure_dirs()
    sec = _load("security_summary.csv")
    if sec is not None:
        plot_security(sec)
        plot_high_risk(sec)
    lat = _load("latency_summary.csv")
    if lat is not None:
        plot_latency(lat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
