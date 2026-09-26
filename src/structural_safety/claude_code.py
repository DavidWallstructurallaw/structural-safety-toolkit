"""Read a strict project MCP configuration subset without contacting servers.

Configuration presence and user-supplied scenario premises remain separate.
No command, endpoint, credential, environment value or helper is returned.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import math
import re
from typing import Any

from .business_templates import get_template
from .model import Diagnostic, Limits, freeze, thaw
from .validation import validate_json


_LIMITATIONS = (
    "Only the supplied project .mcp.json subset is inventoried; local, user, plugin, "
    "connector and managed configurations, and built-in tools are outside scope.",
    "Configuration presence does not establish approval, connectivity, tool availability, "
    "technical capability, authorization or effective protection.",
    "Commands, helpers, URLs and environment expansion are never executed or resolved; "
    "configuration values and unknown field contents are omitted from reports.",
    "The generated memory-handoff scenario covers the three bound roles only. Other "
    "configured servers and unmodeled routes remain outside its declared scope.",
    "The selected template's objects, rights, timing, controls and completeness are supplied "
    "scenario assumptions requiring review; no real deployment protection is verified.",
)
_ASSUMPTIONS = (
    "Without bindings, supply the intended source, shared-memory and publication roles "
    "before requesting a scenario model.",
    "Review the template's source restrictions, version lineage, task grants, control "
    "independence, retained memory, recipients and normal tasks against deployment evidence.",
)
_ROLES = {"source": "if:crm-read", "memory": "if:handoff-memory", "publish": "if:customer-publish"}
_REMOTE = {"http", "streamable-http", "sse", "ws"}
_RESERVED_NAMES = {"workspace", "claude-in-chrome", "computer-use"}


@dataclass(frozen=True, slots=True)
class ClaudeCodeImportResult:
    import_status: str
    model: Mapping[str, Any] | None = None
    diagnostics: tuple[Diagnostic, ...] = ()
    inventory: tuple[Mapping[str, Any], ...] = ()
    assumptions: tuple[str, ...] = _ASSUMPTIONS
    limitations: tuple[str, ...] = _LIMITATIONS
    effective_limits: Limits = field(default_factory=Limits)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model", freeze(self.model))
        object.__setattr__(self, "inventory", tuple(freeze(item) for item in self.inventory))
        for name in ("diagnostics", "assumptions", "limitations"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_schema_version": "sst.claude-code-import/0.1",
            "import_status": self.import_status,
            "model": thaw(self.model),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "inventory": thaw(self.inventory),
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
            "effective_limits": self.effective_limits.to_dict(),
            "analysis_performed": False,
            "execution_performed": False,
        }


class _ImportProblem(Exception):
    def __init__(self, code: str, path: str, message: str, *, resource: bool = False):
        self.diagnostic = Diagnostic(code, path, message)
        self.resource = resource


class _Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.bytes = 0
        self.entries = 0

    def add_entries(self, count: int, path: str) -> None:
        self.entries += count
        if self.entries > self.limits.max_records:
            raise _ImportProblem("max_records", path,
                                 "JSON object members and array entries exceed max_records.", resource=True)


def _load(document: str | bytes, budget: _Budget, path: str) -> dict:
    """Location diagnostics contain fixed labels, never untrusted object keys."""
    try:
        raw = document.encode("utf-8") if isinstance(document, str) else document
    except UnicodeEncodeError as error:
        raise _ImportProblem("invalid_unicode", path, "Input contains invalid Unicode.") from error
    budget.bytes += len(raw)
    if budget.bytes > budget.limits.max_input_bytes:
        raise _ImportProblem("max_input_bytes", path, "Combined input exceeds max_input_bytes.", resource=True)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _ImportProblem("invalid_utf8", path, "Input must be UTF-8.") from error
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > budget.limits.max_depth:
                raise _ImportProblem("max_depth", path, "JSON nesting exceeds max_depth.", resource=True)
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict:
        budget.add_entries(len(items), path)
        value = {}
        for key, item in items:
            if key in value:
                raise _ImportProblem("duplicate_key", path, "Duplicate JSON object key.")
            value[key] = item
        return value

    def number(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise _ImportProblem("non_finite_number", path, "JSON numbers must be finite.")
        return value

    def constant(token: str) -> None:
        raise _ImportProblem("non_standard_number", path, "Nonstandard JSON number.")

    def integer(token: str) -> int:
        try:
            return int(token)
        except ValueError as error:
            raise _ImportProblem("integer_capacity", path, "Integer exceeds parser capacity.", resource=True) from error

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_float=number,
                          parse_int=integer, parse_constant=constant)
        pending = [data]
        while pending:
            current = pending.pop()
            if isinstance(current, dict):
                pending.extend(current.keys())
                pending.extend(current.values())
            elif isinstance(current, list):
                budget.add_entries(len(current), path)
                pending.extend(current)
            elif isinstance(current, str):
                current.encode("utf-8")
    except json.JSONDecodeError as error:
        raise _ImportProblem("invalid_json", path, "Input is not strict JSON.") from error
    except UnicodeEncodeError as error:
        raise _ImportProblem("invalid_unicode", path, "JSON strings contain invalid Unicode.") from error
    except RecursionError as error:
        raise _ImportProblem("parser_capacity", path, "JSON exceeds parser nesting capacity.", resource=True) from error
    if not isinstance(data, dict):
        raise _ImportProblem("root_object", path, "The JSON root must be an object.")
    return data


def _fields(value: dict, allowed: set[str], required: set[str], path: str) -> None:
    if set(value) - allowed:
        raise _ImportProblem("unsupported_field", path, "An unsupported field is present; its name and value are omitted.")
    if required - set(value):
        raise _ImportProblem("missing_field", path, "A required supported field is missing.")


def _string_map(value: Any, path: str) -> None:
    if not isinstance(value, dict) or any(not key or not isinstance(item, str) for key, item in value.items()):
        raise _ImportProblem("string_map", path, "Expected an object with nonempty keys and string values.")


def _inventory(data: dict) -> list[dict]:
    _fields(data, {"mcpServers"}, {"mcpServers"}, "/configuration")
    servers = data["mcpServers"]
    if not isinstance(servers, dict):
        raise _ImportProblem("servers_object", "/configuration/mcpServers", "mcpServers must be an object.")
    result = []
    for index, (name, server) in enumerate(servers.items()):
        path = f"/configuration/mcpServers/server-{index + 1}"
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or name in _RESERVED_NAMES:
            raise _ImportProblem("server_name", path, "Server names must use letters, digits, hyphens or underscores and cannot be reserved.")
        if not isinstance(server, dict):
            raise _ImportProblem("server_object", path, "Each server definition must be an object.")
        transport = server.get("type", "stdio")
        if not isinstance(transport, str) or transport not in _REMOTE | {"stdio"}:
            raise _ImportProblem("unsupported_transport", path, "Unsupported server transport; its value is omitted.")
        if transport == "stdio":
            _fields(server, {"type", "command", "args", "env"}, {"command"}, path)
            if not isinstance(server["command"], str) or not server["command"].strip():
                raise _ImportProblem("command_string", path, "A stdio command must be a nonempty string.")
            args = server.get("args", [])
            if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
                raise _ImportProblem("arguments_array", path, "Arguments must be an array of strings.")
            _string_map(server.get("env", {}), path)
            status = "configured"
        else:
            _fields(server, {"type", "url", "headers", "headersHelper"}, {"type", "url"}, path)
            if not isinstance(server["url"], str):
                raise _ImportProblem("url_string", path, "A remote URL must be a string.")
            _string_map(server.get("headers", {}), path)
            if "headersHelper" in server and (not isinstance(server["headersHelper"], str) or not server["headersHelper"].strip()):
                raise _ImportProblem("helper_string", path, "headersHelper must be a nonempty string.")
            status = "configured" if server["url"].strip() else "unconfigured"
        result.append({
            "server_name": name,
            "transport": "http" if transport == "streamable-http" else transport,
            "configuration_status": status,
            "field_presence": {key: key in server for key in (
                "type", "command", "args", "env", "url", "headers", "headersHelper")},
            "argument_count": len(server.get("args", [])),
            "environment_entry_count": len(server.get("env", {})),
            "header_entry_count": len(server.get("headers", {})),
        })
    return result


def _bindings(data: dict, inventory: list[dict]) -> tuple[str, dict[str, str]]:
    path = "/bindings"
    _fields(data, {"schema_version", "template", "variant", "servers"},
            {"schema_version", "template", "variant", "servers"}, path)
    if data["schema_version"] != "sst.claude-code-bindings/0.1":
        raise _ImportProblem("bindings_schema", path, "Supported bindings schema: sst.claude-code-bindings/0.1.")
    if data["template"] != "memory-handoff":
        raise _ImportProblem("bindings_template", path, "Only the memory-handoff template is supported by this importer.")
    variant = data["variant"]
    if not isinstance(variant, str) or variant not in {"exposed", "controlled"}:
        raise _ImportProblem("bindings_variant", path, "The template variant must be exposed or controlled.")
    servers = data["servers"]
    if not isinstance(servers, dict):
        raise _ImportProblem("bindings_servers", path, "Bindings servers must be an object.")
    _fields(servers, set(_ROLES), set(_ROLES), path)
    if any(not isinstance(name, str) or not name for name in servers.values()):
        raise _ImportProblem("bindings_name", path, "Each role must name a configured server.")
    if len(set(servers.values())) != len(_ROLES):
        raise _ImportProblem("bindings_distinct", path, "This template requires three distinct server bindings.")
    configured = {item["server_name"]: item["configuration_status"] for item in inventory}
    if any(name not in configured for name in servers.values()):
        raise _ImportProblem("bindings_missing_server", path, "A bound server is absent from the configuration.")
    if any(configured[name] != "configured" for name in servers.values()):
        raise _ImportProblem("bindings_unconfigured", path, "A bound remote server has no configured URL.")
    return variant, servers


def _model(variant: str, servers: dict[str, str], inventory: list[dict]) -> dict:
    template = get_template("memory-handoff", variant=variant)
    replacements = {old: "if:claude-code:" + role for role, old in _ROLES.items()}
    snapshot = "snapshot:claude-code-memory-handoff-" + variant
    replacements[template["context"]["snapshot_id"]] = snapshot

    def mapped(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: mapped(item) for key, item in value.items()}
        if isinstance(value, list):
            return [mapped(item) for item in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    model = mapped(template)
    interfaces = {item["id"]: item for item in model["context"]["interfaces"]}
    for role in _ROLES:
        interfaces["if:claude-code:" + role]["evidence_refs"].append("ev:claude-code-bindings")
    model["context"]["declared_scope"] = (
        "Supplied memory-handoff " + variant + " scenario bound to project MCP server roles: "
        + ", ".join(role + "=" + servers[role] for role in _ROLES)
        + ". Only the finite scenario is modeled; MCP capability and approval are unverified.")
    model["context"]["known_limits"].extend(_LIMITATIONS)

    def evidence(identifier: str, acquisition: str, claim: str, scope: list[dict]) -> dict:
        return {
            "id": identifier, "source": "Read-only Claude Code project MCP importer.",
            "acquisition": acquisition, "claim": claim, "scope": scope, "snapshot_id": snapshot,
            "recorded_at": {"state": "unknown", "reason": "Configuration observation time not supplied.", "evidence_refs": []},
            "model_involvement": {"state": "known", "value": "none", "evidence_refs": []},
            "transformations": ["Values omitted; only validated server names, transports and field counts retained."],
            "lineage_refs": {"state": "known", "value": [], "evidence_refs": []},
            "applicability": "unresolved", "limits": list(_LIMITATIONS),
        }

    model["evidence"].append(evidence(
        "ev:claude-code-config", "configuration_read",
        "The supplied JSON contains these server configuration entries: "
        + json.dumps(inventory, ensure_ascii=True, sort_keys=True)
        + ". This claim establishes configuration presence only.", [],
    ))
    model["evidence"].append(evidence(
        "ev:claude-code-bindings", "supplied_assertion",
        "Caller-selected memory-handoff roles and template variant: "
        + json.dumps({"servers": servers, "variant": variant}, sort_keys=True)
        + ". Model permissions and controls remain authored template assumptions.",
        [{"collection": "interfaces", "id": "if:claude-code:" + role} for role in _ROLES],
    ))
    return model


def import_claude_code_json(document: str | bytes, *, bindings_document: str | bytes | None = None,
                           limits: Limits | None = None) -> ClaudeCodeImportResult:
    """Return a redacted inventory, optionally bound to an authored scenario.

    Ordinary input and resource failures return diagnostics. Programmer misuse
    and invalid bundled templates raise exceptions rather than inventing facts.
    """
    if not isinstance(document, (str, bytes)):
        raise TypeError("document must be raw JSON str or bytes")
    if bindings_document is not None and not isinstance(bindings_document, (str, bytes)):
        raise TypeError("bindings_document must be raw JSON str, bytes or None")
    if limits is not None and not isinstance(limits, Limits):
        raise TypeError("limits must be Limits or None")
    limits = limits if limits is not None else Limits()
    inventory: list[dict] = []
    try:
        budget = _Budget(limits)
        inventory = _inventory(_load(document, budget, "/configuration"))
        if bindings_document is None:
            return ClaudeCodeImportResult("inventory_only", inventory=tuple(inventory), effective_limits=limits,
                diagnostics=(Diagnostic("bindings_required", "/bindings",
                                        "Supply explicit role bindings to create a scenario model.", "info"),))
        variant, servers = _bindings(_load(bindings_document, budget, "/bindings"), inventory)
        model = _model(variant, servers, inventory)
        validated = validate_json(json.dumps(model, ensure_ascii=True, allow_nan=False), limits=limits)
        if validated.validation_status == "resource_rejected":
            return ClaudeCodeImportResult("resource_rejected", inventory=tuple(inventory), effective_limits=limits,
                diagnostics=(Diagnostic("generated_model_limit", "/model", "The generated model exceeds caller limits."),))
        if validated.validation_status != "valid":
            raise RuntimeError("Bundled memory-handoff import produced an invalid model")
        return ClaudeCodeImportResult("model_created", model=model, inventory=tuple(inventory),
            assumptions=("The explicit role bindings and selected template are supplied scenario premises.", *_ASSUMPTIONS[1:]),
            effective_limits=limits)
    except _ImportProblem as error:
        return ClaudeCodeImportResult("resource_rejected" if error.resource else "input_invalid",
            inventory=tuple(inventory), diagnostics=(error.diagnostic,), effective_limits=limits)
