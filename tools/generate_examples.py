"""Expand the human-fixed P1-4 model variants into packaged JSON resources.

Development only. Neither the runtime nor its expected answers call this file.
The analyzer always reads the complete generated model, with no implicit grants.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src/structural_safety/examples"
REFS = ["ev:fixture-declaration"]
D_CASES = ("D-behavior", "D-declaration", "D-isolation")
E_CASES = ("E0", "E-version", "E-recipient", "E-purpose", "E-interface", "E-expiry",
           "E-issuer", "E-revoked", "E-unknown", "E-task")
F_CASES = ("F-open", "F-locked")


def fact(value):
    return {"state": "known", "value": value, "evidence_refs": REFS.copy()}


def unknown(reason):
    return {"state": "unknown", "reason": reason, "evidence_refs": REFS.copy()}


def instant(second):
    return (datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat().replace("+00:00", "Z")


def named(records, name):
    return next(record for record in records if record["id"] == name)


def extra_interface(model, identifier, operation="publish"):
    node = deepcopy(named(model["nodes"], "tool:publish"))
    node["id"] = "tool:" + identifier
    model["nodes"].append(node)
    interface = deepcopy(named(model["context"]["interfaces"], "if:publish"))
    interface.update(id="if:" + identifier, node_id=node["id"], operation_ids=[operation])
    model["context"]["interfaces"].append(interface)


def extra_sink(model, name):
    node = deepcopy(named(model["nodes"], "sink:main"))
    node["id"] = name
    model["nodes"].append(node)


def build(case):
    model = json.loads((ROOT / "B.json").read_text())
    auth = model["authorization"]
    actions = model["actions"]
    control = model["controls"][0]
    strict = control["policy_versions"][0]
    private = named(actions, "publish_s_main")
    if case == "C":
        extra_interface(model, "alternate")
        extra_sink(model, "sink:alt")
        alternate = deepcopy(private)
        alternate.update(id="publish_s_alt", interface_id="if:alternate", effect_time=fact(instant(35)))
        alternate["outputs"][0]["location_node_id"] = "sink:alt"
        actions.insert(3, alternate)
        cap = deepcopy(named(auth["capabilities"], "cap:publish_s_main"))
        cap["id"] = "cap:publish_s_alt"
        cap["clauses"][0].update(interfaces=fact(["if:alternate"]), recipients=fact(["sink:alt"]))
        auth["capabilities"].append(cap)
    elif case in D_CASES:
        if case == "D-behavior":
            strict["decision_mode"] = unknown("The refusal algorithm is not established.")
        elif case == "D-isolation":
            control["modification_paths_complete"] = unknown("Policy modification paths and isolation are not established.")
    elif case in E_CASES:
        extra_interface(model, "mirror")
        extra_sink(model, "sink:other")
        model["context"]["purposes"].append({"id": "archive_demo", "description": "A distinct archive purpose"})
        # Every E case has technical and task authority for reading both versions.
        for collection, prefix in (("capabilities", "cap:"), ("task_grants", "grant:")):
            record = deepcopy(named(auth[collection], prefix + "read_s"))
            record["id"] = prefix + "read_s2"
            record["clauses"][0]["objects"] = fact(["S:v2"])
            auth[collection].append(record)
        cap = named(auth["capabilities"], "cap:publish_s_main")
        cap["clauses"][0].update(objects=fact(["S:v1", "S:v2"]),
            interfaces=fact(["if:publish", "if:mirror"]), recipients=fact(["sink:main", "sink:other"]),
            purposes=fact(["external_demo", "archive_demo"]))
        grant = deepcopy(cap)
        grant.update(id="grant:publish_s_main", approval_refs=fact(["approval:owner-task"]))
        if case != "E-task":
            auth["task_grants"].append(grant)
        for clause in named(auth["approval_rights"], "approval:owner-task")["clauses"]:
            clause["interfaces"]["value"].append("if:mirror")
            clause["recipients"]["value"].append("sink:other")
            clause["purposes"]["value"].append("archive_demo")
        coverage = strict["coverage"]["value"][0]
        coverage["interfaces"]["value"].append("if:mirror")
        coverage["recipients"]["value"].append("sink:other")
        coverage["purposes"]["value"].append("archive_demo")
        release = {k: deepcopy(cap[k]) for k in ("issuer", "validity", "revocation", "evidence_refs")}
        narrow = deepcopy(cap["clauses"][0])
        narrow.update(objects=fact(["S:v1"]), interfaces=fact(["if:publish"]),
                      recipients=fact(["sink:main"]), purposes=fact(["external_demo"]))
        release.update(id="release:E0", clauses=[narrow], restriction_ids=fact(["restriction:S-v1"]),
                       approval_refs=fact(["approval:owner-release"]),
                       validity=fact({"not_before": instant(30), "expires_at": instant(60)}))
        if case == "E-issuer":
            release["issuer"] = fact("principal:outsider")
        elif case == "E-revoked":
            release["revocation"] = fact({"revoked": True, "at": instant(39)})
        elif case == "E-unknown":
            release["revocation"] = unknown("Revocation at the requested effect time is not known.")
        auth["release_exceptions"] = [release]
        private["effect_time"] = fact(instant(60 if case == "E-expiry" else 40))
        if case == "E-version":
            for port in private["inputs"] + private["outputs"]:
                port["object_version_id"] = "S:v2"
            private["success_dependencies"] = ["read_s2"]
            read = deepcopy(named(actions, "read_s"))
            read.update(id="read_s2", effect_time=fact(instant(12)))
            for port in read["inputs"] + read["outputs"]:
                port["object_version_id"] = "S:v2"
            actions.append(read)
        elif case == "E-recipient":
            private["outputs"][0]["location_node_id"] = "sink:other"
        elif case == "E-interface":
            private["interface_id"] = "if:mirror"
        elif case == "E-purpose":
            private["purpose_id"] = "archive_demo"
        for name, second in (("copy_s_internal", 70), ("read_p", 75), ("publish_p_main", 80)):
            named(actions, name)["effect_time"] = fact(instant(second))
    elif case in F_CASES:
        model["context"]["operation_definitions"].append({"id": "policy_update", "semantic_kind": "policy_update", "evidence_refs": REFS.copy()})
        extra_interface(model, "policy", "policy_update")
        model["context"]["purposes"].append({"id": "policy_management", "description": "Select one predeclared policy version"})
        weak = deepcopy(strict)
        weak.update(id="policy:weak", decision_mode=fact("deny_table"))
        control["policy_versions"].append(weak)
        control["modifiable_fields"] = fact(["decision_mode"])
        after = deepcopy(private)
        after.update(id="publish_s_after", effect_time=fact(instant(40)))
        private.update(id="publish_s_before", effect_time=fact(instant(25)))
        target = {"control_id": "gate:main", "policy_version_id": "policy:weak", "fields": ["decision_mode"]}
        select = {k: deepcopy(private[k]) for k in ("task_id", "workflow_id", "context_id", "actor_id", "evidence_refs")}
        select.update(id="select_weak", operation_id="policy_update", interface_id="if:policy",
                      purpose_id="policy_management", effect_time=fact(instant(35)), inputs=[], outputs=[],
                      success_dependencies=[], conditions=[], effects=[{"id": "select", "kind": "select_policy", **target}])
        actions.extend([select, after])
        cap = deepcopy(named(auth["capabilities"], "cap:publish_s_main"))
        cap["id"] = "cap:select_weak"
        cap["clauses"][0].update(objects=fact([]), policy_targets=fact([target]),
                                operations=fact(["policy_update"]), interfaces=fact(["if:policy"]),
                                recipients=fact(["node:gate-main"]), purposes=fact(["policy_management"]))
        if case == "F-open":
            auth["capabilities"].append(cap)
    else:
        raise ValueError(case)
    actions.sort(key=lambda a: (a["effect_time"]["value"], a["id"]))
    return model


if __name__ == "__main__":
    for case in ("C", *D_CASES, *E_CASES, *F_CASES):
        (ROOT / (case + ".json")).write_text(json.dumps(build(case), indent=2) + "\n")
