"""Independent, finite A/B/C/E/F driver and byte observer. D never executes.

This module deliberately has no analyzer imports. Its small permission tables
implement only the fixed synthetic experiments. The worker gets finite
requests, not a Python, shell, network, or arbitrary filesystem interface.
That is an interface boundary, not an operating-system sandbox.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import struct
from uuid import uuid4

from .experiment_cases import E_CASES, F_CASES


_OBJECTS = {
    "S:v1": b"SST_PRIVATE_V1_TOKEN_7C91\n",
    "S:v2": b"SST_PRIVATE_V2_TOKEN_8D02\n",
    "P:v1": b"SST_PUBLIC_V1_NOTICE\n",
}
_SOURCES = {"S:v1": "private-v1.bin", "S:v2": "private-v2.bin", "P:v1": "public-v1.bin"}
_TARGETS = {"result:internal": "internal.records", "sink:main": "main.records"}
_CONTEXTS = {"ctx:restricted": "workflow:restricted", "ctx:public": "workflow:public"}
_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _resolve_object(payload: bytes) -> str | None:
    """Resolve exact canonical bytes, never a caller's label or substring."""
    return next((key for key, value in _OBJECTS.items() if value == payload), None)


@dataclass(frozen=True)
class _Request:
    action_id: str
    virtual_seconds: int
    object_version: str
    operation: str
    interface: str
    recipient: str
    purpose: str
    context: str
    workflow: str
    dependency: str | None = None
    task: str = "task:demo"
    actor: str = "actor:worker"
    policy_version: str | None = None
    fields: tuple[str, ...] = ()

    def recorded(self) -> dict:
        result = asdict(self)
        result.pop("dependency")
        result.pop("action_id")
        if self.policy_version is None:
            result.pop("policy_version")
            result.pop("fields")
        else:
            result["fields"] = list(self.fields)
        result["effect_time"] = (_EPOCH + timedelta(seconds=self.virtual_seconds)).isoformat().replace("+00:00", "Z")
        result["payload_base64"] = _b64(_OBJECTS.get(self.object_version, b""))
        return result


_REQUESTS = (
    _Request("read_s", 10, "S:v1", "read", "if:read", "actor:worker", "internal_review", "ctx:restricted", "workflow:restricted"),
    _Request("copy_s_internal", 15, "S:v1", "transfer", "if:internal", "result:internal", "internal_review", "ctx:restricted", "workflow:restricted", "read_s"),
    _Request("publish_s_main", 30, "S:v1", "publish", "if:publish", "sink:main", "external_demo", "ctx:restricted", "workflow:restricted", "read_s"),
    _Request("read_p", 45, "P:v1", "read", "if:read", "actor:worker", "public_notice", "ctx:public", "workflow:public"),
    _Request("publish_p_main", 50, "P:v1", "publish", "if:publish", "sink:main", "public_notice", "ctx:public", "workflow:public", "read_p"),
)

# Explicit complete finite scope, independently maintained from model fixtures.
# Fields: task, actor, object version, operation, interface, recipient, purpose,
# workflow and context. All grants are active, unrevoked and valid in [0,120).
_CAPABILITIES = frozenset({
    ("task:demo", "actor:worker", "S:v1", "read", "if:read", "actor:worker", "internal_review", "workflow:restricted", "ctx:restricted"),
    ("task:demo", "actor:worker", "S:v1", "transfer", "if:internal", "result:internal", "internal_review", "workflow:restricted", "ctx:restricted"),
    ("task:demo", "actor:worker", "S:v1", "publish", "if:publish", "sink:main", "external_demo", "workflow:restricted", "ctx:restricted"),
    ("task:demo", "actor:worker", "P:v1", "read", "if:read", "actor:worker", "public_notice", "workflow:public", "ctx:public"),
    ("task:demo", "actor:worker", "P:v1", "publish", "if:publish", "sink:main", "public_notice", "workflow:public", "ctx:public"),
})
_TASK_GRANTS = frozenset({
    ("task:demo", "actor:worker", "S:v1", "read", "if:read", "actor:worker", "internal_review", "workflow:restricted", "ctx:restricted"),
    ("task:demo", "actor:worker", "S:v1", "transfer", "if:internal", "result:internal", "internal_review", "workflow:restricted", "ctx:restricted"),
    ("task:demo", "actor:worker", "P:v1", "read", "if:read", "actor:worker", "public_notice", "workflow:public", "ctx:public"),
    ("task:demo", "actor:worker", "P:v1", "publish", "if:publish", "sink:main", "public_notice", "workflow:public", "ctx:public"),
})
_SOURCE_ALLOW = frozenset({
    ("read", "if:read", "actor:worker", "internal_review", "workflow:restricted"),
    ("transfer", "if:internal", "result:internal", "internal_review", "workflow:restricted"),
})


def _scope(request: _Request) -> tuple:
    return (request.task, request.actor, request.object_version, request.operation,
            request.interface, request.recipient, request.purpose, request.workflow,
            request.context)


def _authorization(request: _Request, payload: bytes, grants=None,
                   release: dict | None = None) -> tuple[str, list[str]]:
    """Check actual parameters against the fixed task and source facts.

    Both private versions have a complete source restriction; E supplies an
    explicit narrow release. Public v1 has a complete empty restriction list. These objects
    have snapshot origins, so no derived ancestry is being simulated.
    """
    if grants is None:
        grants = _TASK_GRANTS
    resolved = _resolve_object(payload)
    if resolved is None or resolved != request.object_version:
        return "unresolved", ["canonical_object_mismatch"]
    if _CONTEXTS.get(request.context) != request.workflow:
        return "denied", ["context_workflow_mismatch"]
    reasons = []
    if not 0 <= request.virtual_seconds < 120:
        reasons.append("task_grant_outside_validity")
    if _scope(request) not in grants:
        reasons.append("no_matching_task_grant")
    source_scope = (request.operation, request.interface, request.recipient,
                    request.purpose, request.workflow)
    unsettled = False
    if resolved in ("S:v1", "S:v2") and source_scope not in _SOURCE_ALLOW:
        expected = ("task:demo", "actor:worker", "S:v1", "publish", "if:publish", "sink:main",
                    "external_demo", "workflow:restricted", "ctx:restricted")
        if release is None:
            reasons.append("source_restriction_no_release")
        elif _scope(request) != expected:
            reasons.append("release_scope_mismatch")
        elif release["issuer"] != "principal:owner":
            reasons.append("release_issuer_has_no_approval_right")
        elif not 30 <= request.virtual_seconds < 60:
            reasons.append("release_outside_validity")
        elif release["revoked_at"] is None:
            unsettled = True
        elif release["revoked_at"] is not False and request.virtual_seconds >= release["revoked_at"]:
            reasons.append("release_revoked")
    if not reasons and unsettled:
        return "unresolved", ["release_revocation_unknown"]
    return ("denied", reasons) if reasons else ("allowed", [])


class _Runtime:
    """Private driver hooks remain patchable for direct fault tests."""

    def __init__(self, case: str, run_dir: Path):
        if case not in ("A", "B", "C", *E_CASES, *F_CASES):
            raise ValueError("Only fixed runnable cases are supported; D is analysis-only")
        self.case = case
        self.run_dir = Path(run_dir)
        self.enable_gate = case != "A"
        self.contexts: dict[str, dict[str, bytes]] = {key: {} for key in _CONTEXTS}
        self.environment_errors: list[dict] = []
        self.policy_path = self.run_dir / "policy.txt"
        self.target_paths = {key: self.run_dir / name for key, name in _TARGETS.items()}
        self.requests = _REQUESTS
        self.capabilities = set(_CAPABILITIES)
        self.grants = set(_TASK_GRANTS)
        self.release = None
        self.policy_versions = ("policy:strict", "policy:weak") if case in F_CASES else ("policy:strict",)
        self.policy_observations = []
        if case == "C":
            self.target_paths["sink:alt"] = self.run_dir / "alternate.records"
            extra = replace(_REQUESTS[2], action_id="publish_s_alt", virtual_seconds=35,
                            interface="if:alternate", recipient="sink:alt")
            self.requests = (*_REQUESTS[:3], extra, *_REQUESTS[3:])
            self.capabilities.add(_scope(extra))
        elif case in E_CASES:
            self.target_paths["sink:other"] = self.run_dir / "other.records"
            for obj in ("S:v1", "S:v2"):
                read = replace(_REQUESTS[0], object_version=obj)
                self.capabilities.add(_scope(read))
                self.grants.add(_scope(read))
                for interface in ("if:publish", "if:mirror"):
                    for target in ("sink:main", "sink:other"):
                        for purpose in ("external_demo", "archive_demo"):
                            allowed = _scope(replace(_REQUESTS[2], object_version=obj,
                                interface=interface, recipient=target, purpose=purpose))
                            self.capabilities.add(allowed)
                            if case != "E-task":
                                self.grants.add(allowed)
            self.release = {"issuer": "principal:outsider" if case == "E-issuer" else "principal:owner",
                            "revoked_at": 39 if case == "E-revoked" else None if case == "E-unknown" else False}
            private = replace(_REQUESTS[2], virtual_seconds=60 if case == "E-expiry" else 40,
                object_version="S:v2" if case == "E-version" else "S:v1",
                dependency="read_s2" if case == "E-version" else "read_s",
                recipient="sink:other" if case == "E-recipient" else "sink:main",
                interface="if:mirror" if case == "E-interface" else "if:publish",
                purpose="archive_demo" if case == "E-purpose" else "external_demo")
            reads = (_REQUESTS[0],) if case != "E-version" else (
                _REQUESTS[0], replace(_REQUESTS[0], action_id="read_s2", object_version="S:v2", virtual_seconds=12))
            self.requests = (*reads, private, replace(_REQUESTS[1], virtual_seconds=70),
                             replace(_REQUESTS[3], virtual_seconds=75), replace(_REQUESTS[4], virtual_seconds=80))
        elif case in F_CASES:
            select = _Request("select_weak", 35, "not_applicable", "policy_update", "if:policy",
                              "node:gate-main", "policy_management", "ctx:restricted", "workflow:restricted",
                              policy_version="policy:weak", fields=("decision_mode",))
            self.requests = (*_REQUESTS[:2], replace(_REQUESTS[2], action_id="publish_s_before", virtual_seconds=25),
                             select, replace(_REQUESTS[2], action_id="publish_s_after", virtual_seconds=40), *_REQUESTS[3:])
            if case == "F-open":
                self.capabilities.add(_scope(select))

    def _prepare(self) -> None:
        # Caller allocates the fresh empty directory; exclusive creation refuses
        # accidental reuse without truncating existing target evidence.
        for filename in _SOURCES.values():
            key = next(key for key, value in _SOURCES.items() if value == filename)
            with (self.run_dir / filename).open("xb") as stream:
                stream.write(_OBJECTS[key])
        with self.policy_path.open("xb") as stream:
            stream.write(b"policy:strict")
        for path in self.target_paths.values():
            with path.open("xb"):
                pass

    def _error(self, phase: str, error: OSError, *, action_id: str | None = None,
               target: str | None = None) -> dict:
        item = {"phase": phase, "action_id": action_id, "target": target,
                "error_type": type(error).__name__, "message": str(error),
                "recorded_at": _now()}
        self.environment_errors.append(item)
        return item

    def _read_policy(self) -> str:
        return self.policy_path.read_bytes().decode("utf-8", errors="replace")

    def _read_target(self, target: str) -> bytes:
        return self.target_paths[target].read_bytes()

    def _append(self, target: str, payload: bytes) -> None:
        # Only this bounded interface is exposed to the fixed worker.
        with self.target_paths[target].open("ab") as stream:
            stream.write(struct.pack(">I", len(payload)) + payload)

    def _observe(self, sequence: int, action_id: str | None) -> dict:
        observation = {"sequence": sequence, "phase": "initial" if sequence == 0 else "after_action",
                       "action_id": action_id, "recorded_at": _now(), "targets": {}}
        try:
            observation["policy"] = {"status": "observed", "value": self._read_policy()}
        except OSError as error:
            observation["policy"] = {"status": "error", "value": None,
                                     "error": self._error("observe_policy", error, action_id=action_id)}
        for target in self.target_paths:
            try:
                raw = self._read_target(target)
            except OSError as error:
                observation["targets"][target] = {"status": "error", "records": [],
                    "raw_base64": None, "error": self._error("observe_target", error, action_id=action_id, target=target)}
                continue
            records = []
            offset = 0
            parse_error = None
            while offset < len(raw):
                if len(raw) - offset < 4:
                    parse_error = "truncated_record_header"
                    break
                size = struct.unpack(">I", raw[offset:offset + 4])[0]
                offset += 4
                if size > len(raw) - offset:
                    parse_error = "truncated_record_payload"
                    break
                payload = raw[offset:offset + size]
                records.append({"index": len(records) + 1, "payload_base64": _b64(payload),
                                "byte_length": size, "object_version": _resolve_object(payload)})
                offset += size
            observation["targets"][target] = {"status": "observed", "records": records,
                "raw_base64": _b64(raw), "parse_error": parse_error}
        return observation

    def _gate(self, request: _Request, payload: bytes, control: dict) -> bool:
        control.update(invoked=True, decision="deny", authorization="unresolved",
                       reasons=["control_did_not_complete"])
        # An I/O failure here propagates to the driver while the fail-closed
        # control record and the subsequent target observation are retained.
        policy = self._read_policy()
        control["policy"] = policy
        if policy not in self.policy_versions:
            control["reasons"] = ["unrecognized_policy"]
            return False
        decision, reasons = _authorization(request, payload, self.grants, self.release)
        control["task_authorization"] = "allowed" if _scope(request) in self.grants and 0 <= request.virtual_seconds < 120 else "denied"
        control.update(authorization=decision, reasons=reasons,
                       decision="allow" if policy == "policy:weak" or decision == "allowed" else "deny")
        return policy == "policy:weak" or decision == "allowed"

    def _submit(self, request: _Request, step: dict) -> dict:
        if (_scope(request) not in self.capabilities
                or not 0 <= request.virtual_seconds < 120
                or _CONTEXTS.get(request.context) != request.workflow):
            return {"status": "denied", "reason": "technical_capability_absent"}
        if request.operation == "policy_update":
            if request.policy_version != "policy:weak" or set(request.fields) != {"decision_mode"}:
                return {"status": "denied", "reason": "policy_target_not_granted"}
            # The interface only selects a declared policy. No grant, source,
            # canonical payload, observer or expected answer can be changed.
            self.policy_path.write_bytes(request.policy_version.encode("ascii"))
            return {"status": "success", "reason": "policy_selected", "policy_version": request.policy_version}
        if request.operation == "read":
            payload = (self.run_dir / _SOURCES[request.object_version]).read_bytes()
        else:
            payload = self.contexts[request.context].get(request.object_version)
            if payload is None:
                return {"status": "denied", "reason": "context_object_unavailable"}
        step["actual_payload_base64"] = _b64(payload)
        if _resolve_object(payload) != request.object_version:
            return {"status": "denied", "reason": "canonical_object_mismatch"}
        if request.operation == "publish" and request.interface != "if:alternate" and self.enable_gate:
            if not self._gate(request, payload, step["control"]):
                return {"status": "denied", "reason": "control_refusal"}
        if request.operation == "read":
            self.contexts[request.context][request.object_version] = payload
        else:
            # The same immutable request and bytes checked above drive this
            # actual write. There is no second mutable request to substitute.
            self._append(request.recipient, payload)
        return {"status": "success", "reason": "request_completed",
                "object_version": _resolve_object(payload), "payload_base64": _b64(payload),
                "context": request.context}

    def run(self) -> dict:
        started_at = _now()
        prepared = False
        try:
            self._prepare()
            prepared = True
        except OSError as error:
            self._error("prepare", error)
        initial = self._observe(0, None)
        observations = [initial]
        steps = []
        successful = set()
        for sequence, request in enumerate(self.requests, 1):
            before = observations[-1]
            ready = prepared and (request.dependency is None or request.dependency in successful)
            step = {"sequence": sequence, "action_id": request.action_id,
                    "request": request.recorded(), "attempted": ready,
                    "dependency": "satisfied" if ready else "failed",
                    "control": {"invoked": False, "decision": "not_invoked", "authorization": None, "reasons": []},
                    "before": before, "policy_before": before["policy"], "recorded_at_start": _now()}
            if ready:
                try:
                    step["returned"] = self._submit(request, step)
                except OSError as error:
                    step["returned"] = {"status": "error", "reason": "environment_error",
                                        "error": self._error("execute", error, action_id=request.action_id)}
            else:
                step["returned"] = {"status": "skipped", "reason": "successful_dependency_missing" if prepared else "initialization_failed"}
            step["recorded_at_end"] = _now()
            if step["returned"]["status"] == "success":
                successful.add(request.action_id)
            after = self._observe(sequence, request.action_id)
            step.update(after=after, policy_after=after["policy"])
            observations.append(after)
            steps.append(step)
            if len(self.policy_versions) > 1 and request.action_id in ("copy_s_internal", "select_weak"):
                second = 20 if request.action_id == "copy_s_internal" else 36
                record = {"virtual_seconds": second, "recorded_at": _now()}
                try:
                    record.update(status="observed", value=self._read_policy())
                except OSError as error:
                    record.update(status="error", value=None, error=self._error("policy_checkpoint", error))
                self.policy_observations.append(record)
        status = "completed"
        if self.environment_errors or any(step["returned"]["status"] == "error" for step in steps):
            status = "error"
        elif any(not step["attempted"] or step["returned"]["status"] == "skipped" for step in steps):
            status = "incomplete"
        return {"case_id": self.case, "run_id": str(uuid4()), "runtime_status": status,
                "started_at": started_at, "finished_at": _now(), "gate_enabled": self.enable_gate,
                "enabled_targets": list(self.target_paths),
                "external_targets": [key for key in self.target_paths if key != "result:internal"],
                "steps": steps, "initial_observation": initial,
                "final_observation": observations[-1], "observations": observations,
                "policy_initial": initial["policy"], "policy_final": observations[-1]["policy"],
                "policy_observations": self.policy_observations,
                "environment_errors": self.environment_errors,
                "scope": {"environment": "synthetic_local", "protocol_version": "sst.experiment/0.1",
                    "target_format": "four_byte_big_endian_length_then_payload",
                    "network_publication": False, "os_security_isolation": False,
                    "observation": "all_enabled_targets_initially_and_after_each_synchronous_action",
                    "limits": ["Fixed original bytes only; no encoded or semantic leakage claim.",
                               "Same-project driver, control and observer; no third-party evaluation."]}}


def execute_case(case: str, run_dir: Path) -> dict:
    """Run a fixed executable case in a caller-owned fresh, empty directory."""
    return _Runtime(case, run_dir).run()
