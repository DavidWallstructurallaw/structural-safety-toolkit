"""Keep structural validation separate from the future safety analysis."""

from importlib.resources import files
import json
import unittest

from structural_safety import validate_json


def fixture():
    return json.loads(files("structural_safety").joinpath("examples/A.json").read_text(encoding="utf-8"))


class StageBoundaryTests(unittest.TestCase):
    def assert_valid_model(self, document):
        result = validate_json(json.dumps(document))
        self.assertEqual("valid", result.validation_status, result.diagnostics)
        report = result.to_dict()
        self.assertFalse(report["analysis_performed"])
        self.assertEqual(["input_validation"], report["supported_capabilities"])
        self.assertNotIn("safe", report)
        self.assertNotIn("findings", report)
        return result

    def test_circular_success_dependencies_are_retained_for_analysis(self):
        document = fixture()
        first, second = document["actions"][:2]
        first["success_dependencies"] = [second["id"]]
        second["success_dependencies"] = [first["id"]]
        result = self.assert_valid_model(document)
        self.assertEqual(document, result.model.to_dict())

    def test_mutually_exclusive_conditions_do_not_become_bad_input(self):
        document = fixture()
        document["actions"][0]["conditions"] = [
            {"key": "mode", "operator": "eq", "value": "internal", "evidence_refs": []},
            {"key": "mode", "operator": "eq", "value": "public", "evidence_refs": []},
        ]
        self.assert_valid_model(document)

    def test_expired_and_revoked_permission_is_still_structurally_valid(self):
        document = fixture()
        grant = document["authorization"]["task_grants"][0]
        grant["validity"] = {
            "state": "known",
            "value": {"not_before": "1998-01-01T00:00:00Z", "expires_at": "1999-01-01T00:00:00Z"},
            "evidence_refs": [],
        }
        grant["revocation"] = {
            "state": "known",
            "value": {"revoked": True, "at": "1998-06-01T00:00:00Z"},
            "evidence_refs": [],
        }
        self.assert_valid_model(document)


if __name__ == "__main__":
    unittest.main()
