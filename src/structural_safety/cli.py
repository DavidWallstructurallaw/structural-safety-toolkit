"""Command boundary for validation, analysis, local experiments and file access."""

import argparse
from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Sequence

from . import __version__, _version_source
from .api import Limits, analyze_json, run_demo, validate_json
from .experiment_cases import CHOICES, D_CASES


_BUDGET_NAMES = (
    "max_states", "max_transition_checks", "max_scope_combinations",
    "max_clause_checks", "max_findings",
)


class _OperationalError(Exception):
    """A known operational failure with a non-sensitive message."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="structural-safety",
        description="Validate and analyze explicit AI agent deployment models, and run local demos.",
        epilog="Supports finite model analysis with SS001-SS006 and fixed A-F scenarios.",
    )
    version_label = f"structural-safety {__version__}"
    if _version_source != "installed metadata":
        version_label += f" ({_version_source})"
    parser.add_argument("--version", action="version", version=version_label)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("validate", "Check input structure; no safety analysis is performed."),
        ("analyze", "Analyze supported paths and report findings and unresolved scope."),
        ("demo", "Run fixed A-F scenarios; D is analysis-only, other cases use local synthetic targets."),
    ):
        command = commands.add_parser(name, help=help_text)
        if name == "demo":
            command.add_argument("scenario", metavar="SCENARIO", choices=CHOICES,
                                 help="A, B, C, D/E/F groups or named subcases, or all; D is analysis-only.")
            command.add_argument("--work-dir", metavar="DIR", type=Path,
                                 help="Retain observations in a new run directory under DIR.")
        else:
            command.add_argument("input", metavar="INPUT", help="Local JSON file, or - for stdin.")
        command.add_argument("--format", choices=("json", "markdown"), default="json")
        command.add_argument("--output", metavar="PATH", help="Atomically save the report to a file.")
        if name in {"analyze", "demo"}:
            defaults = Limits()
            for budget in _BUDGET_NAMES:
                command.add_argument(
                    "--" + budget.replace("_", "-"), type=_positive_int,
                    default=getattr(defaults, budget), metavar="N",
                    help=f"Positive caller budget (default: {getattr(defaults, budget)}).",
                )
    return parser


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("budget must be a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("budget must be a positive integer")
    return parsed


def _read_document(name: str, max_bytes: int) -> bytes:
    try:
        if name == "-":
            return sys.stdin.buffer.read(max_bytes + 1)
        with open(name, "rb") as stream:
            return stream.read(max_bytes + 1)
    except (OSError, ValueError) as error:
        raise _OperationalError("Cannot read the input file or stream.") from error


def _refuse_input_alias(input_name: str, output: Path) -> None:
    if input_name == "-":
        try:
            source_stat = os.fstat(sys.stdin.fileno())
            if stat.S_ISREG(source_stat.st_mode) and output.exists():
                output_stat = output.stat()
                if (source_stat.st_dev, source_stat.st_ino) == (output_stat.st_dev, output_stat.st_ino):
                    raise _OperationalError("Output must not replace the file supplying stdin.")
        except (OSError, ValueError) as error:
            raise _OperationalError("Cannot verify the stdin and output file boundary.") from error
        return
    source = Path(input_name)
    try:
        if source.resolve() == output.resolve():
            raise _OperationalError("Output must not replace the input file.")
        if output.exists() and os.path.samefile(source, output):
            raise _OperationalError("Output must not replace an alias of the input file.")
    except (OSError, RuntimeError, ValueError) as error:
        raise _OperationalError("Cannot verify that input and output are different files.") from error


def _refuse_demo_alias(output: Path, protected_roots: tuple[Path, ...]) -> None:
    """Keep runtime data and observations intact when saving another report."""
    try:
        destination = output.resolve()
        for root in protected_roots:
            if destination.is_relative_to(root.resolve()):
                raise _OperationalError("Output must not replace files in a retained experiment run.")
            if output.exists():
                for source in root.rglob("*"):
                    if source.is_file() and os.path.samefile(source, output):
                        raise _OperationalError("Output must not replace an alias of experiment evidence.")
    except (OSError, RuntimeError, ValueError) as error:
        raise _OperationalError("Cannot verify the experiment and output file boundary.") from error


def _write_output(output: Path, content: str, input_name: str | None = None,
                  protected_roots: tuple[Path, ...] = ()) -> None:
    def check_boundary() -> None:
        if input_name is not None:
            _refuse_input_alias(input_name, output)
        _refuse_demo_alias(output, protected_roots)

    check_boundary()
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=output.parent,
            prefix=".structural-safety-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(content)
        check_boundary()
        os.replace(temporary, output)
        temporary = None
    except (OSError, UnicodeError, ValueError) as error:
        raise _OperationalError("Cannot save the report.") from error
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                pass


def _diagnostic(message: str) -> None:
    try:
        print(f"structural-safety: {message}", file=sys.stderr)
    except (OSError, UnicodeError):
        pass


def _main(argv: Sequence[str] | None) -> int:
    arguments = _parser().parse_args(argv)
    protected_roots: tuple[Path, ...] = ()
    if arguments.command == "demo":
        result = run_demo(arguments.scenario, work_dir=arguments.work_dir,
                          limits=Limits(**{name: getattr(arguments, name) for name in _BUDGET_NAMES}))
        exit_code = _demo_exit(result)
        if arguments.output is not None:
            protected_roots = _demo_roots(result, arguments.work_dir)
    else:
        document = _read_document(arguments.input, Limits().max_input_bytes)
    if arguments.command == "validate":
        result = validate_json(document)
        if result.validation_status not in {
            "valid", "input_invalid", "unsupported_schema", "resource_rejected"
        }:
            raise RuntimeError("Unrecognized validation result status")
        exit_code = 0 if result.validation_status == "valid" else 2
    elif arguments.command == "analyze":
        limits = Limits(**{
            name: getattr(arguments, name) for name in _BUDGET_NAMES
        })
        result = analyze_json(document, limits=limits)
        exit_code = _analysis_exit(result)
    if arguments.format == "json":
        content = json.dumps(result.to_dict(), ensure_ascii=True, sort_keys=True,
                             indent=2, allow_nan=False) + "\n"
    else:
        content = result.to_markdown()
    if arguments.output is not None:
        _write_output(Path(arguments.output), content, getattr(arguments, "input", None), protected_roots)
        _diagnostic({"validate": "Validation", "analyze": "Analysis", "demo": "Demo"}[arguments.command]
                    + " report saved.")
    else:
        try:
            # Reports use the same UTF-8 encoding on disk and through pipes,
            # including Windows shells with a legacy text-stream encoding.
            # Embedded callers can still redirect to a text-only stream.
            binary_stdout = getattr(sys.stdout, "buffer", None)
            if binary_stdout is None:
                sys.stdout.write(content)
            else:
                sys.stdout.flush()
                binary_stdout.write(content.encode("utf-8"))
            sys.stdout.flush()
        except (OSError, UnicodeError) as error:
            raise _OperationalError("Cannot write the report to stdout.") from error
    return exit_code


def _demo_roots(result: object, work_dir: Path | None) -> tuple[Path, ...]:
    roots = [Path(result.run_directory)] if result.run_directory is not None else []
    if work_dir is not None:
        try:
            # The reserved prefix belongs to run_demo. A sibling summary file
            # is permitted; previous run evidence must survive later commands.
            if work_dir.is_dir():
                roots.extend(path for path in work_dir.glob("sst-demo-*") if path.is_dir())
        except (OSError, ValueError) as error:
            raise _OperationalError("Cannot verify retained experiment directories.") from error
    return tuple(dict.fromkeys(roots))


def _demo_exit(result: object) -> int:
    status = result.demo_status
    if status not in {"completed", "input_invalid", "unsupported_scenario", "resource_rejected", "error"}:
        raise RuntimeError("Unrecognized demo result status")
    if status == "error" or result.environment_errors or any(
        case.get("runtime_status") == "error" or case.get("environment_errors") for case in result.cases
    ):
        return 5
    if status in {"input_invalid", "unsupported_scenario", "resource_rejected"}:
        return 2
    verdict = result.protocol_verdict
    if verdict not in {"matched", "mismatched", "inconclusive", "not_tested"}:
        raise RuntimeError("Unrecognized demo protocol verdict")
    if verdict == "mismatched":
        return 4
    if verdict != "matched" or not result.cases or any(
        case.get("runtime_status") != "completed" and not (
            case.get("case_id") in D_CASES and case.get("runtime_status") == "not_tested"
            and case.get("analysis_comparison", {}).get("verdict") == "matched"
            and not case.get("actual_effects") and not case.get("runtime", {}).get("observations")
        ) for case in result.cases
    ):
        return 3
    return 0


def _has_unfinished_check(value: object) -> bool:
    """Retain unfinished per-obligation scope even without a summary item."""
    if isinstance(value, Mapping):
        if value.get("check_status") in {"partial", "not_checked"}:
            return True
        if value.get("obligation_status") == "unresolved":
            return True
        if value.get("model_coverage") == "unresolved":
            return True
        return any(_has_unfinished_check(item) for item in value.values())
    if isinstance(value, (tuple, list)):
        return any(_has_unfinished_check(item) for item in value)
    return False


def _analysis_exit(result: object) -> int:
    status = result.analysis_status
    if status in {"input_invalid", "unsupported_schema", "resource_rejected"}:
        return 2
    if status not in {"partial", "completed_for_supported_scope"}:
        raise RuntimeError("Unrecognized analysis result status")
    if (
        status == "partial" or result.unresolved_items or result.unsupported_items
        or result.truncation or _has_unfinished_check(result.obligations)
        or _has_unfinished_check(result.coverage) or _has_unfinished_check(result.action_results)
    ):
        return 3
    return 1 if result.findings else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI without converting internal failures into model unknowns."""
    try:
        return _main(argv)
    except SystemExit as error:
        # argparse handles help, version and command-usage diagnostics.
        return int(error.code) if isinstance(error.code, int) else 2
    except KeyboardInterrupt:
        _diagnostic("Interrupted; the command did not complete.")
        return 130
    except _OperationalError as error:
        _diagnostic(str(error))
        return 5
    except Exception:
        _diagnostic("Internal error; the command did not complete.")
        return 70
