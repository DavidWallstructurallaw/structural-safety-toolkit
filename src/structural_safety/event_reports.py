"""Retain ordinary imported event claims without promoting their provenance."""

from datetime import datetime


def import_reports(document):
    actions = {action["id"]: action for action in document["actions"]}
    for event in sorted(document.get("events", ()), key=lambda item: item["id"]):
        action = actions[event["action_id"]]
        occurred = event["occurred_at"]
        declared = action["effect_time"]
        comparison = "unresolved"
        if event["reported_event_kind"] in ("execution", "effect_observed"):
            if occurred["state"] == declared["state"] == "known":
                actual = datetime.fromisoformat(occurred["value"].replace("Z", "+00:00"))
                expected = datetime.fromisoformat(declared["value"].replace("Z", "+00:00"))
                comparison = "matches_declared_time" if actual == expected else "differs_from_declared_time"
        else:
            comparison = "not_applicable_to_effect_time"
        declared_objects = {port["object_version_id"] for port in (*action["inputs"], *action["outputs"])}
        yield {
            "event_id": event["id"], "run_id": event["run_id"], "action_id": event["action_id"],
            "reported_event_kind": event["reported_event_kind"], "object_ids": event["object_ids"],
            "observer_id": event["observer_id"], "reported_environment": event["environment"],
            "occurred_at": occurred, "recorded_at": event["recorded_at"],
            "submitted_verified": event.get("verified"), "claimed_origin": event.get("claimed_origin"),
            "time_comparison": comparison,
            "objects_outside_declared_action": sorted(set(event["object_ids"]) - declared_objects),
            "evidence_refs": event["evidence_refs"], "evidence_basis": ["external_report"],
            "check_status": "checked", "direct_observation": False, "observed_effect": "not_tested",
            "details_omitted": True,
            "limits": ["Imported event claims do not establish actual execution, effect, authorization, or control efficacy.",
                       "No event kind implies the next kind; absent events do not establish absence of effects.",
                       "Time or object differences preserve a report/model discrepancy without choosing either as verified truth."],
        }
