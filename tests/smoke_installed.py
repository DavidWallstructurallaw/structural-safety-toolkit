"""Check a wheel installation from outside its source checkout.

CI copies this script into a temporary directory and runs it with the fresh
environment's Python in isolated mode. It is separate from unit discovery.
"""

from importlib import metadata, resources
import json
import os
from pathlib import Path
import subprocess
import sys

import structural_safety


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
            if not analysis.analysis_performed or analysis.analysis_status not in {
                "partial", "completed_for_supported_scope"
            }:
                raise RuntimeError(f"Installed analysis API did not analyze {filename}.")
            for command in commands:
                completed = subprocess.run(
                    [*command, "analyze", str(input_path)],
                    env=environment, capture_output=True, text=True, check=False,
                )
                if completed.returncode not in {0, 1, 3} or completed.stderr:
                    raise RuntimeError("Installed analysis CLI failed operationally.")
                if json.loads(completed.stdout) != analysis.to_dict():
                    raise RuntimeError("Installed CLI and API analysis reports differ.")
    print(f"Installed wheel {installed_version}: validation/analysis APIs, both CLI entries and A/B resources passed.")


if __name__ == "__main__":
    main()
