"""공용: attacker 패키지 경로 등록 및 실험 메타데이터."""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKER_ROOT = REPO_ROOT / "attacker"
RESULTS_DIR = REPO_ROOT / "experiments" / "results"
RAW_DIR = REPO_ROOT / "experiments" / "raw"
PLOTS_DIR = REPO_ROOT / "experiments" / "plots"

for path in (ATTACKER_ROOT,):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def ensure_dirs() -> None:
    for d in (RESULTS_DIR, RAW_DIR, PLOTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_run_metadata(extra: dict) -> Path:
    """run_metadata.json (지시서 §12). 실측 결과의 재현 조건을 기록한다."""
    ensure_dirs()
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "note": (
            "S3 수치는 BoundKey **시뮬레이터** 기반이다. BLE RTT / Secure Element "
            "signing latency / firmware RAM/Flash 는 실제 하드웨어에서 재측정해야 한다 "
            "(지시서 §23, §34). NOT VERIFIED ON HARDWARE."
        ),
        **extra,
    }
    path = RESULTS_DIR / "run_metadata.json"
    path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
