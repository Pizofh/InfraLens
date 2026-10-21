"""Command-line entry point for InfraLens."""

from __future__ import annotations

import argparse
import sys
from uuid import UUID

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
    scan.add_argument(
        "--scope-id", type=_scope_id_argument, help="operator-supplied UUID for the scan scope"
    )
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
        return _run_scan(args)
    _parser().print_help()
    return 0


def _scope_id_argument(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("scope-id must be a canonical UUID") from exc
    if str(parsed) != value.lower():
        raise argparse.ArgumentTypeError("scope-id must be a canonical UUID")
    return str(parsed)


def _run_scan(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        print("infralens: scan requires Linux", file=sys.stderr)
        return 2
    if args.output == "-" or "://" in args.output:
        print("infralens: output must be a local file path", file=sys.stderr)
        return 2

    from infralens.reporting import OutputPathError, format_summary, write_snapshot
    from infralens.scan import scan_local

    try:
        snapshot = scan_local(args.scope_id)
    except KeyboardInterrupt:
        print("infralens: scan interrupted; no snapshot was published", file=sys.stderr)
        return 130
    except Exception:
        print("infralens: could not collect a valid Linux snapshot", file=sys.stderr)
        return 1

    try:
        write_snapshot(snapshot, args.output, overwrite=args.overwrite)
    except KeyboardInterrupt:
        print("infralens: scan interrupted", file=sys.stderr)
        return 130
    except FileExistsError:
        print(
            "infralens: output file already exists; use --overwrite to replace it", file=sys.stderr
        )
        return 2
    except (OutputPathError, FileNotFoundError, NotADirectoryError):
        print("infralens: output path is invalid", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("infralens: could not validate or write the snapshot", file=sys.stderr)
        return 1

    print(format_summary(snapshot))
    if args.fail_on_partial and any(
        item.status != "ok" or item.coverage != "complete" for item in snapshot.collectors
    ):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
