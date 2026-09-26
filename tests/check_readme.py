"""Execute README API and CLI examples with an installed package, outside source.

Run with the fresh environment's Python, passing the README path. Installation,
build, and source-test commands are checked by the enclosing packaging workflow.
"""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python check_readme.py /path/to/README.md")
    readme = Path(sys.argv[1]).read_text(encoding="utf-8")
    python = Path(sys.executable)
    console = python.with_name("structural-safety.exe" if os.name == "nt" else "structural-safety")
    if not console.is_file():
        raise RuntimeError(f"Installed console entry point is missing: {console}")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)

    def run(command: list[str], directory: str, expected: int, label: str) -> None:
        result = subprocess.run(command, cwd=directory, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=120)
        if result.returncode != expected:
            raise RuntimeError(f"README example failed: {label}\n"
                               f"Expected exit {expected}; got {result.returncode}.\n"
                               f"{result.stderr or result.stdout[-2000:]}")

    snippets = re.findall(r"```python\n(.*?)\n```", readme, re.S)
    commands = []
    with tempfile.TemporaryDirectory(prefix="sst-readme-") as directory:
        for index, snippet in enumerate(snippets, start=1):
            run([str(python), "-I", "-c", snippet], directory, 0, f"Python block {index}")
        for block in re.findall(r"```sh\n(.*?)\n```", readme, re.S):
            for line in block.splitlines():
                if line.startswith("structural-safety "):
                    arguments = shlex.split(line)[1:]
                    command = [str(console), *arguments]
                elif line.startswith("python -m structural_safety "):
                    arguments = shlex.split(line)[3:]
                    command = [str(python), "-I", "-m", "structural_safety", *arguments]
                else:
                    continue
                expected = 0
                if arguments[0] == "import-claude-code" and "--bindings" not in arguments:
                    expected = 3
                elif arguments[0] == "analyze":
                    expected = 3 if arguments[1] == "D-behavior.json" else 1
                run(command, directory, expected, line)
                commands.append(line)
    if not snippets or not commands:
        raise RuntimeError("README must contain executable Python and CLI examples.")
    print(f"README: {len(snippets)} Python examples and {len(commands)} CLI commands passed outside checkout.")


if __name__ == "__main__":
    main()
