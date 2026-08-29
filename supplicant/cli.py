"""Command-line interface for supplicant.

Exit codes: 0 clean, 1 findings >= min-severity, 2 scan error, 3 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import ScanReport, severity_rank

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_USAGE = 3

BANNER = "supplicant — does this version look like itself?"


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; the spec promises exit 3."""

    def error(self, message):  # noqa: A003
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(EXIT_USAGE)


def _detect_scan_kind(path: str) -> str:
    name = Path(path).name.lower()
    if name == "package-lock.json":
        return "lockfile"
    if name == "package.json":
        return "manifest"
    if name in ("requirements.txt", "Pipfile.lock", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"):
        return "lockfile"
    if path.endswith((".lock", ".lock.json", ".txt", ".json")):
        return "lockfile"  # unsupported lockfiles then surface a clear parse error
    return "target"


def _load_report(ctx, kind: str, arg: str, max_depth: int) -> ScanReport:
    from . import pipeline

    if kind == "lockfile":
        return pipeline.scan_lockfile(ctx, arg)
    if kind == "manifest":
        return pipeline.scan_manifest(ctx, arg, max_depth=max_depth)
    return pipeline.scan_target(ctx, arg, max_depth=max_depth)


def _run_scan(args: argparse.Namespace) -> int:
    from . import pipeline
    from .graph import build_graph, to_dot, to_json
    from .report.render import render_json, render_sarif, render_text

    ctx = pipeline.build_context(args.cache_dir, config={"osv": not args.no_osv})
    report = _load_report(ctx, args.kind, args.target, args.max_depth)

    if args.format == "text":
        print(render_text(report, min_severity=args.min_severity, color=not args.no_color))
    elif args.format == "sarif":
        print(render_sarif(report))
    else:
        if args.format == "dot":
            print(to_dot(build_graph(report.artifacts, report.edges, report.signals)))
        elif args.format == "json":
            print(render_json(report))
        else:
            print(to_json(build_graph(report.artifacts, report.edges, report.signals)))
        for err in report.errors:
            print(f"error: {err}", file=sys.stderr)

    findings = report.signals_at_or_above(args.min_severity)
    # Diff signals live in report.diffs[].signals (excluded from the top-level
    # list to avoid double-printing) but must still gate the exit code.
    if not findings:
        floor = severity_rank(args.min_severity)
        findings = [
            s for d in report.diffs for s in d.signals if severity_rank(s.severity) >= floor
        ]
    if findings:
        return EXIT_FINDINGS
    if report.errors:
        return EXIT_ERROR
    return EXIT_OK


def _parse_diff_pair(a: str, b: str):
    from .pipeline import parse_target
    from .resolvers.tree import _version_tuple

    art_a = parse_target(a)
    art_b = parse_target(b)
    if art_a.name != art_b.name or art_a.ecosystem != art_b.ecosystem:
        raise ValueError(f"diff requires the same package: got {art_a.key} vs {art_b.key}")
    if art_a.version == "latest" or art_b.version == "latest":
        raise ValueError("diff requires explicit versions (no 'latest')")
    # Swap so the diff always runs oldest -> newest.
    if _version_tuple(art_a.version) > _version_tuple(art_b.version):
        art_a, art_b = art_b, art_a
    return art_a.ecosystem, art_a.name, art_a.version, art_b.version


def _run_diff(args: argparse.Namespace) -> int:
    from . import pipeline
    from .report.render import render_diff_text, render_json, render_sarif

    try:
        ecosystem, name, v_a, v_b = _parse_diff_pair(args.version_a, args.version_b)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE

    ctx = pipeline.build_context(args.cache_dir, config={"osv": not args.no_osv})
    outcome = pipeline.compute_diff(ctx, ecosystem, name, v_a, v_b)

    for err in ctx.config.get("_errors", []):
        print(f"error: {err}", file=sys.stderr)

    if args.format == "json":
        # Diff signals live in diffs[].signals; don't double-report them under
        # the top-level "signals" key.
        report = ScanReport(
            artifacts=[outcome.artifact],
            diffs=[outcome],
            errors=list(ctx.config.get("_errors", [])),
        )
        print(render_json(report))
    elif args.format == "sarif":
        report = ScanReport(
            artifacts=[outcome.artifact],
            diffs=[outcome],
            errors=list(ctx.config.get("_errors", [])),
        )
        print(render_sarif(report))
    else:
        print(render_diff_text(outcome, min_severity=args.min_severity, color=not args.no_color))

    if ctx.config.get("_errors"):
        return EXIT_ERROR
    floor = severity_rank(args.min_severity)
    if any(severity_rank(s.severity) >= floor for s in outcome.signals):
        return EXIT_FINDINGS
    return EXIT_OK


def _run_forensics(args: argparse.Namespace) -> int:
    from . import pipeline

    ctx = pipeline.build_context(args.cache_dir, config={"osv": False})
    info = pipeline.run_forensics(ctx, args.target)
    print(json.dumps(info, indent=2))
    return EXIT_OK


def _run_fence(args: argparse.Namespace) -> int:
    from . import pipeline

    ctx = pipeline.build_context(args.cache_dir, config={"osv": False})
    identities = pipeline.run_fence(ctx, args.name)
    print(json.dumps(identities, indent=2))
    return EXIT_OK


def _run_server(args: argparse.Namespace) -> int:
    print("server mode is not implemented in v0.1", file=sys.stderr)
    return EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="supplicant",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"supplicant {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="recursive dependency-tree scan")
    scan.add_argument("target", help="pkg | pkg@version | npm:pkg@version | pypi:pkg==1.2.3 | lockfile path")
    scan.add_argument("--kind", choices=["target", "lockfile", "manifest"], default=None,
                      help="force input interpretation (default: auto-detect from name)")
    scan.add_argument("--max-depth", type=int, default=10)
    scan.add_argument("--format", choices=["text", "json", "dot", "graph", "sarif"], default="text")
    _add_common(scan)
    scan.set_defaults(func=_run_scan)

    diff = sub.add_parser("diff", help="flagship: security-scored diff of two versions")
    diff.add_argument("version_a", help="e.g. keyv@5.2.0 or npm:keyv@5.2.0")
    diff.add_argument("version_b", help="e.g. keyv@6.0.0")
    diff.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    _add_common(diff)
    diff.set_defaults(func=_run_diff)

    graph = sub.add_parser("graph", help="render the security graph as DOT/JSON")
    graph.add_argument("target")
    graph.add_argument("--format", choices=["dot", "json"], default="dot")
    graph.add_argument("--max-depth", type=int, default=10)
    _add_common(graph)
    graph.set_defaults(func=_run_scan)

    forensics = sub.add_parser("forensics", help="reconstruct a (possibly yanked) version")
    forensics.add_argument("target", help="e.g. event-stream@3.3.6")
    _add_common(forensics)
    forensics.set_defaults(func=_run_forensics)

    fence = sub.add_parser("fence", help="who owns this name across ecosystems")
    fence.add_argument("name")
    _add_common(fence)
    fence.set_defaults(func=_run_fence)

    server = sub.add_parser("server", help="web UI / REST (stub in v0.1)")
    server.add_argument("--port", type=int, default=8080)
    _add_common(server)
    server.set_defaults(func=_run_server)

    return parser


def _add_common(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--cache-dir", type=Path, default=None,
                     help="cache + archive root (default ~/.cache/supplicant)")
    sub.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="medium",
                     help="minimum severity that counts as a finding / shows in text output (default medium; low+informational signals are shown with --min-severity low|info)")
    sub.add_argument("--no-osv", action="store_true", help="skip OSV.dev advisory queries")
    sub.add_argument("--no-color", action="store_true")


def main(argv: list[str] | None = None) -> int:
    from . import pipeline

    parser = build_parser()
    args = parser.parse_args(argv)

    # --format is shared across scan/graph; unify the graph alias before dispatch
    if getattr(args, "command", None) == "graph" and args.format == "json":
        args.format = "graph"

    if args.cache_dir is None:
        args.cache_dir = pipeline.DEFAULT_CACHE_DIR

    if getattr(args, "kind", None) is None and getattr(args, "command", None) in ("scan", "graph"):
        args.kind = _detect_scan_kind(args.target)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:  # noqa: BLE001 - CLI boundary
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
