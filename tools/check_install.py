"""Install one built wheel and exercise it in a fresh external environment."""

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import venv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("distribution_directory", type=Path)
    args = parser.parse_args()
    wheels = list(args.distribution_directory.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel in the distribution directory.")
    wheel = wheels[0].resolve()
    checkout = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    print(platform.platform(), platform.python_implementation(), platform.python_version(), flush=True)
    print(f"Checking distribution: {wheel.name}", flush=True)
    with tempfile.TemporaryDirectory(prefix="sst-wheel-", dir=os.environ.get("RUNNER_TEMP")) as directory:
        root = Path(directory).resolve()
        if root.is_relative_to(checkout):
            raise SystemExit("The installed check must run outside the source checkout.")
        virtual_environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(virtual_environment)
        python = virtual_environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

        def run(*arguments: str) -> None:
            subprocess.run([str(python), *arguments], cwd=root, env=environment, check=True)

        run("-m", "pip", "install", "--no-index", "--no-deps", str(wheel))
        run("-m", "pip", "check")
        for source in ("tests/smoke_installed.py", "tests/check_readme.py", "README.md"):
            shutil.copyfile(checkout / source, root / Path(source).name)
        run("-I", str(root / "smoke_installed.py"))
        run("-I", str(root / "check_readme.py"), str(root / "README.md"))


if __name__ == "__main__":
    main()
