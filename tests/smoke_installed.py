"""Check a wheel installation from outside its source checkout.

CI copies this script into a temporary directory and runs it with the fresh
environment's Python in isolated mode. It is separate from unit discovery.
"""

import base64
from importlib import metadata, resources
import json
import os
from pathlib import Path
import subprocess
import sys

import structural_safety


def check_all(report: dict) -> None:
    expected = ("A", "B", "C", "D-behavior", "D-declaration", "D-isolation", "E0", "E-version",
                "E-recipient", "E-purpose", "E-interface", "E-expiry", "E-issuer", "E-revoked", "E-unknown",
                "E-task", "F-open", "F-locked")
    if (report["scenario"] != "all" or report["protocol_verdict"] != "matched"
            or report["demo_status"] != "completed" or report["environment_errors"]
            or tuple(c["case_id"] for c in report["cases"]) != expected):
        raise RuntimeError("Installed all selection did not preserve its 18-case protocol.")
    for case in report["cases"]:
        name = case["case_id"]
        if case["analysis_comparison"]["verdict"] != "matched":
            raise RuntimeError("Installed case analysis did not match its expected semantics.")
        if name.startswith("D-"):
            if (case["runtime_status"] != "not_tested" or case["actual_effects"] or case["runtime"]["observations"]
                    or case["normal_tasks"] != {"U-internal": "not_tested", "U-public": "not_tested"}):
                raise RuntimeError("Installed D case falsely claimed execution or utility.")
            continue
        if (case["runtime_status"] != "completed" or case["runtime_comparison"]["verdict"] != "matched"
                or case["normal_tasks"] != {"U-internal": "success", "U-public": "success"}):
            raise RuntimeError("Installed executable case lost observations or normal work.")
        violations = [e for e in case["actual_effects"] if e["classification"] == "observed_boundary_violation"]
        if bool(violations) != (name in ("A", "C", "F-open")):
            raise RuntimeError("Installed case has an incorrect observed authorization result.")
        if name == "E0" and not any(e["object_version"] == "S:v1" and e["target"] == "sink:main"
                                   and e["classification"] == "authorized_effect" for e in case["actual_effects"]):
            raise RuntimeError("Installed E0 lost its lawful narrow release.")
        if name == "E-unknown":
            private = next(s for s in case["runtime"]["steps"] if s["action_id"] == "publish_s_main")
            if private["control"]["authorization"] != "unresolved":
                raise RuntimeError("Installed E-unknown collapsed missing revocation evidence.")
        if name in ("F-open", "F-locked"):
            policy = "policy:weak" if name == "F-open" else "policy:strict"
            after = next(s for s in case["runtime"]["steps"] if s["action_id"] == "publish_s_after")
            if case["policy_after"]["value"] != policy or after["attempted"] is not True:
                raise RuntimeError("Installed F lost its actual policy state or second attempt.")


def check_demo(report: dict, scenario: str) -> None:
    if (report["result_schema_version"] != "sst.demo/0.1"
            or report["scenario"] != scenario or report["demo_status"] != "completed"
            or report["protocol_verdict"] != "matched" or report["environment_errors"]):
        raise RuntimeError(f"Installed demo {scenario} did not complete its protocol.")
    if report["scope"]["network_transmission"] is not False:
        raise RuntimeError("Installed demo did not retain its local observation scope.")
    if len(report["cases"]) != 1:
        raise RuntimeError("Installed A/B demo unexpectedly expanded its scenario.")
    case = report["cases"][0]
    if (case["case_id"] != scenario or case["runtime_status"] != "completed"
            or case["protocol_verdict"] != "matched"
            or case["normal_tasks"] != {"U-internal": "success", "U-public": "success"}):
        raise RuntimeError("Installed demo did not preserve both normal tasks.")
    observation = case["runtime_comparison"]
    if (observation["evidence_basis"] != ["runtime_observation"]
            or observation["control_assurance"] != ("scoped_evidence" if scenario == "B" else "not_applicable")):
        raise RuntimeError("Installed demo did not preserve its achieved, scoped observation evidence.")
    runtime = case["runtime"]
    if len(runtime["steps"]) != 5 or len(runtime["observations"]) != 6:
        raise RuntimeError("Installed demo lost required requests or observations.")
    private = runtime["steps"][2]
    if private["action_id"] != "publish_s_main" or private["attempted"] is not True:
        raise RuntimeError("Installed demo skipped the restricted request.")
    if (private["control"]["invoked"] is not (scenario == "B")
            or private["returned"]["status"] != ("denied" if scenario == "B" else "success")):
        raise RuntimeError("Installed demo did not preserve the A/B control difference.")
    private_bytes = b"SST_PRIVATE_V1_TOKEN_7C91\n"
    public_bytes = b"SST_PUBLIC_V1_NOTICE\n"
    expected = {"result:internal": [private_bytes],
                "sink:main": ([private_bytes] if scenario == "A" else []) + [public_bytes]}
    final_targets = runtime["final_observation"]["targets"]
    if set(final_targets) != set(expected):
        raise RuntimeError("Installed demo did not observe every enabled target.")
    for target, payloads in expected.items():
        observed = final_targets[target]
        framed_bytes = b"".join(len(payload).to_bytes(4, "big") + payload for payload in payloads)
        if (observed["status"] != "observed" or observed["parse_error"] is not None
                or base64.b64decode(observed["raw_base64"], validate=True) != framed_bytes):
            raise RuntimeError("Installed demo target bytes differ from the fixed protocol.")
    violations = [effect for effect in case["actual_effects"]
                  if effect["classification"] == "observed_boundary_violation"]
    if bool(violations) != (scenario == "A"):
        raise RuntimeError("Installed demo lost the observed violation distinction.")
    if any(finding["observed_effect"] != "not_tested" for finding in case["analysis"]["findings"]):
        raise RuntimeError("Installed demo promoted model findings to runtime observations.")
    if scenario == "B" and not any(
        finding["control_assurance"] == "declaration_only"
        for finding in case["analysis"]["findings"]
    ):
        raise RuntimeError("Installed demo overwrote B's original declaration-only assurance.")


def main() -> None:
    package_file = Path(structural_safety.__file__).resolve()
    if not package_file.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("Smoke check imported a package outside the fresh environment.")
    installed_version = metadata.version("structural-safety-toolkit")
    if structural_safety.__version__ != installed_version:
        raise RuntimeError("Package version does not match installed metadata.")
    if metadata.requires("structural-safety-toolkit"):
        raise RuntimeError("The installed package unexpectedly declares runtime dependencies.")

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    console = Path(sys.executable).with_name("structural-safety")
    commands = ([str(console)], [sys.executable, "-I", "-m", "structural_safety"])
    for filename in ("A.json", "B.json"):
        resource = resources.files("structural_safety").joinpath("examples", filename)
        result = structural_safety.validate_json(resource.read_bytes())
        if result.validation_status != "valid" or result.analysis_performed is not False:
            raise RuntimeError(f"Installed API did not structurally validate {filename}.")
        with resources.as_file(resource) as input_path:
            for command in commands:
                completed = subprocess.run(
                    [*command, "validate", str(input_path)],
                    env=environment, capture_output=True, text=True, check=True,
                )
                if completed.stderr or json.loads(completed.stdout) != result.to_dict():
                    raise RuntimeError("Installed CLI and API validation reports differ.")
            analysis = structural_safety.analyze_json(resource.read_bytes())
            if not analysis.analysis_performed or analysis.analysis_status != "completed_for_supported_scope":
                raise RuntimeError(f"Installed analysis API did not analyze {filename}.")
            for command in commands:
                completed = subprocess.run(
                    [*command, "analyze", str(input_path)],
                    env=environment, capture_output=True, text=True, check=False,
                )
                if completed.returncode != 1 or completed.stderr:
                    raise RuntimeError("Installed analysis CLI failed operationally.")
                if json.loads(completed.stdout) != analysis.to_dict():
                    raise RuntimeError("Installed CLI and API analysis reports differ.")
        scenario = filename.removesuffix(".json")
        demo = structural_safety.run_demo(scenario)
        if not isinstance(demo, structural_safety.DemoResult) or demo.run_directory is not None:
            raise RuntimeError("Installed demo API did not return its self-contained default result.")
        check_demo(demo.to_dict(), scenario)
        for command in commands:
            completed = subprocess.run(
                [*command, "demo", scenario],
                env=environment, capture_output=True, text=True, check=False,
            )
            if completed.returncode != 0 or completed.stderr:
                raise RuntimeError("Installed demo CLI did not match its expected protocol.")
            # Separate runs have distinct timestamps and identifiers. Compare
            # semantic outcomes and observed bytes rather than entire reports.
            check_demo(json.loads(completed.stdout), scenario)
    check_all(structural_safety.run_demo("all").to_dict())
    for command in commands:
        completed = subprocess.run([*command, "demo", "all"], env=environment, capture_output=True, text=True)
        if completed.returncode != 0 or completed.stderr:
            raise RuntimeError("Installed all CLI selection failed.")
        check_all(json.loads(completed.stdout))
    resources_in_wheel = list(resources.files("structural_safety").joinpath("examples").iterdir())
    models = [path for path in resources_in_wheel if path.name.endswith(".json")]
    if len(models) != 18 or any(structural_safety.validate_json(path.read_bytes()).validation_status != "valid" for path in models):
        raise RuntimeError("Installed package must contain 18 structurally valid expanded models.")
    print(f"Installed wheel {installed_version}: validation/analysis/demo APIs, both CLI entries and all 18 resources passed.")


if __name__ == "__main__":
    main()
