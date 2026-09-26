"""Render public results without adding analysis conclusions or runtime claims."""

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
import json
import string
from typing import Any
import unicodedata


def _plain(value: Any) -> Any:
    """Convert only the result's chosen fields to standard JSON values."""
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_plain(item) for item in sorted(value)]
    return value


def validation_to_dict(result: Any) -> dict[str, Any]:
    """Return the public result, explicitly excluding the internal model."""
    return {
        "result_schema_version": result.result_schema_version,
        "validation_status": result.validation_status,
        "schema_version": result.schema_version,
        "analysis_performed": result.analysis_performed,
        "supported_capabilities": list(result.supported_capabilities),
        "diagnostics": _plain(result.diagnostics),
        "effective_limits": _plain(result.effective_limits),
        "unsupported_items": _plain(result.unsupported_items),
    }


def _markdown_text(value: Any) -> str:
    """Display untrusted values as text, including inside Markdown tables."""
    text = "not provided" if value is None else str(value)
    rendered: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            rendered.append("\\\\u" + format(ord(character), "04x"))
        elif character == "&":
            rendered.append("&amp;")
        elif character == "<":
            rendered.append("&lt;")
        elif character == ">":
            rendered.append("&gt;")
        elif character in string.punctuation:
            rendered.append("\\" + character)
        else:
            rendered.append(character)
    return "".join(rendered)


def validation_to_markdown(result: Any) -> str:
    """Render a small validation report; validation is not a safety decision."""
    report = validation_to_dict(result)
    lines = [
        "# Structural Safety Toolkit input validation",
        "",
        f"Status: {_markdown_text(report['validation_status'])}",
        "",
        "This report checks input structure only. Authorization, control coverage, "
        "and deployment safety have not been analyzed.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Result schema | {_markdown_text(report['result_schema_version'])} |",
        f"| Input schema | {_markdown_text(report['schema_version'])} |",
        f"| Analysis performed | {_markdown_text(str(report['analysis_performed']).lower())} |",
        f"| Unsupported items reported | {len(report['unsupported_items'])} |",
        "",
        "## Diagnostics",
        "",
    ]
    if report["diagnostics"]:
        lines.extend([
            "| Severity | Code | Location | Message |",
            "|---|---|---|---|",
        ])
        for item in report["diagnostics"]:
            cells = (item["severity"], item["code"], item["path"], item["message"])
            lines.append("| " + " | ".join(_markdown_text(cell) for cell in cells) + " |")
    else:
        lines.append("No structural diagnostics were reported.")
    if report["unsupported_items"]:
        lines.extend(["", "## Unsupported items", ""])
        lines.append("The following input items are recorded without evaluating their meaning.")
        lines.extend(["", "| ID | Reason | Affected references |", "|---|---|---|"])
        for item in report["unsupported_items"]:
            cells = (item.get("id", "not provided"), item.get("reason", "not provided"),
                     item.get("affected_refs", "not provided"))
            lines.append("| " + " | ".join(_markdown_text(cell) for cell in cells) + " |")
    lines.extend(["", "## Effective limits", "", "| Limit | Value |", "|---|---|"])
    for name, value in sorted(report["effective_limits"].items()):
        lines.append(f"| {_markdown_text(name)} | {_markdown_text(value)} |")
    lines.append("")
    return "\n".join(lines)


def analysis_to_dict(result: Any) -> dict[str, Any]:
    """Serialize the public analysis envelope, never an internal model/state."""
    report = {
        "result_schema_version": result.result_schema_version,
        "rule_version": result.rule_version,
    }
    for name in (
        "analysis_status", "schema_version", "analysis_performed", "diagnostics",
        "findings", "unresolved_items", "obligations", "input_completeness",
        "supported_capabilities", "unsupported_items", "effective_limits",
        "budget_usage", "truncation", "action_results", "coverage", "scope",
    ):
        report[name] = _plain(getattr(result, name))
    return report


def _markdown_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False)
    elif isinstance(value, bool):
        value = str(value).lower()
    return _markdown_text(value)


def _record_section(lines: list[str], title: str, records: list[dict[str, Any]]) -> None:
    """Include every record field, preserving witness sequence and axes."""
    lines.extend(["", "## " + title, ""])
    if not records:
        lines.append("No records.")
        return
    for number, record in enumerate(records, 1):
        lines.extend([f"### Record {number}", "", "| Field | Value |", "|---|---|"])
        for name, value in record.items():
            lines.append(f"| {_markdown_text(name)} | {_markdown_value(value)} |")
        lines.append("")


def analysis_to_markdown(result: Any) -> str:
    """Show bounded model deductions with their unresolved and evidence limits."""
    report = analysis_to_dict(result)
    lines = [
        "# Structural Safety Toolkit analysis",
        "",
        f"Status: {_markdown_text(report['analysis_status'])}",
        "",
        "This report analyzes an explicit model within the supported scope and "
        "effective limits. Model deductions do not establish runtime protection. "
        "No runtime experiment is performed by this command.",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for name in ("result_schema_version", "rule_version", "schema_version",
                 "analysis_performed", "supported_capabilities", "scope"):
        lines.append(f"| {_markdown_text(name)} | {_markdown_value(report[name])} |")
    for name, title in (
        ("diagnostics", "Input diagnostics"),
        ("findings", "Findings and witnesses"),
        ("action_results", "Action results"),
        ("obligations", "Obligations and check status"),
        ("coverage", "Coverage"),
        ("unresolved_items", "Unresolved items"),
        ("unsupported_items", "Unsupported scope"),
        ("input_completeness", "Input completeness"),
        ("truncation", "Truncation"),
    ):
        _record_section(lines, title, report[name])
    lines.extend(["", "## Effective limits and budget usage", "", "| Limit | Cap | Used |", "|---|---|---|"])
    for name, cap in sorted(report["effective_limits"].items()):
        used = report["budget_usage"].get(name, report["budget_usage"].get(name.removeprefix("max_")))
        lines.append(f"| {_markdown_text(name)} | {cap} | {_markdown_value(used)} |")
    lines.extend(["", "Budget counters: " + _markdown_value(report["budget_usage"]), ""])
    return "\n".join(lines)
