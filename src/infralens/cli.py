"""Command-line entry point for InfraLens."""

from __future__ import annotations

import argparse
import sys

from infralens import __version__


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="infralens",
        description="Discover and review evidence about a Linux host.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="inspect the local Linux host")
    scan.add_argument("--local", action="store_true", required=True, help="select the local host")
    scan.add_argument("--output", required=True, help="path for the JSON snapshot")
    scan.add_argument("--scope-id", help="operator-supplied UUID for the scan scope")
    scan.add_argument("--overwrite", action="store_true", help="replace an existing snapshot")
    scan.add_argument(
        "--fail-on-partial",
        action="store_true",
        help="return a nonzero status when collection is incomplete",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return its process exit status."""
    args = _parser().parse_args(argv)
    if args.command == "scan":
        print("infralens: scan is not implemented yet", file=sys.stderr)
        return 1
    _parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
