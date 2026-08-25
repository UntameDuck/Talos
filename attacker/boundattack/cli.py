"""BoundAttack CLI (지시서 §6).

    boundattack attack token-replay
    boundattack attack high-risk-abuse --arm S3
    boundattack attack all --arm all --runs 100 --out experiments/raw/run.jsonl
    boundattack list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .attacks import ALL_ATTACKS, ATTACK_FUNCS
from .recorder import AttackOutcome, ResultWriter
from .runner import run_matrix

ARMS = ["S0", "S1", "S2", "S3"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boundattack",
        description="BoundAuth attack simulator / experiment runner (research use).",
    )
    parser.add_argument("--version", action="version", version=f"boundattack {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_attack = sub.add_parser("attack", help="run one attack (or 'all')")
    p_attack.add_argument("name", choices=[*ALL_ATTACKS, "all"], help="attack name")
    p_attack.add_argument(
        "--arm",
        default="all",
        choices=[*ARMS, "all"],
        help="target arm (default: all)",
    )
    p_attack.add_argument("--runs", type=int, default=1, help="repetitions per (attack, arm)")
    p_attack.add_argument("--out", type=Path, default=None, help="JSONL output path")
    p_attack.add_argument("--quiet", action="store_true", help="suppress per-run lines")

    sub.add_parser("list", help="list available attacks")
    return parser


def _cmd_list() -> int:
    print("Available attacks:")
    for name in ALL_ATTACKS:
        doc = (ATTACK_FUNCS[name].__doc__ or "").strip().splitlines()[0]
        print(f"  {name:<22} {doc}")
    return 0


def _cmd_attack(args: argparse.Namespace) -> int:
    attacks = ALL_ATTACKS if args.name == "all" else [args.name]
    arms = ARMS if args.arm == "all" else [args.arm]

    writer = ResultWriter(args.out) if args.out else None
    outcomes: list[AttackOutcome] = run_matrix(
        attacks=attacks,
        arms=arms,
        runs=args.runs,
        writer=writer,
        on_outcome=None if args.quiet else _print_outcome,
    )

    _print_summary(outcomes)
    # 예상과 어긋난 결과가 있으면 비정상 종료코드로 알린다.
    mismatches = [o for o in outcomes if o.matched_expectation is False]
    return 1 if mismatches else 0


def _print_outcome(o: AttackOutcome) -> None:
    status = "SUCCESS" if o.attack_succeeded else "blocked"
    flag = ""
    if o.matched_expectation is False:
        flag = "  <-- UNEXPECTED"
    print(
        f"  [{o.arm}] {o.attack:<22} {status:<8} "
        f"http={o.status_code} code={o.error_code or '-'}{flag}"
    )


def _print_summary(outcomes: list[AttackOutcome]) -> None:
    print("\nsummary (attack x arm): success/total")
    grid: dict[tuple[str, str], list[AttackOutcome]] = {}
    for o in outcomes:
        grid.setdefault((o.attack, o.arm), []).append(o)
    for (attack, arm), items in sorted(grid.items()):
        succ = sum(1 for i in items if i.attack_succeeded)
        print(f"  {attack:<22} {arm}: {succ}/{len(items)}")


def main(argv: list[str] | None = None) -> int:
    # Windows 콘솔(cp949)에서 유니코드 출력이 깨지지 않도록 UTF-8 로 강제한다.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    if args.command == "list":
        return _cmd_list()
    if args.command == "attack":
        return _cmd_attack(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
