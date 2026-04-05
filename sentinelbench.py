"""
SentinelBench — entry point.

Usage:
    python sentinelbench.py --technique T1003.001
    python sentinelbench.py --suite v1
"""

import argparse
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinelbench",
        description="Detection quality benchmarking for Microsoft Sentinel.",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--technique",
        metavar="TECHNIQUE_ID",
        help="Run a single ATT&CK technique (e.g. T1003.001).",
    )
    group.add_argument(
        "--suite",
        metavar="SUITE",
        choices=["v1"],
        help="Run a predefined suite of techniques (e.g. v1).",
    )

    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Write JSON results to FILE (default: print to stdout).",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.technique:
        print(f"[stub] Running single technique: {args.technique}")
    elif args.suite:
        print(f"[stub] Running suite: {args.suite}")

    # TODO: wire up core.simulation_runner → core.metrics_engine → core.kql_generator


if __name__ == "__main__":
    sys.exit(main())
