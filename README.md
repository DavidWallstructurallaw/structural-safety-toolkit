# Structural Safety Toolkit

A local Python toolkit for describing AI agent execution topology, task authorization, information flows, control coverage, and intervention conditions.

**Current milestone: P1-4, fixed A-F scenarios.** This development build validates deployment descriptions, analyzes finite `read`, `transfer`, and `policy_update` actions with SS001 and SS005 diagnostics, and provides 18 fixed scenarios: 15 local experiments and three analysis-only D contrasts. Analysis reports separate technical feasibility, authorization, modeled control behavior, and evidence limits. Experiment reports retain actual target observations and task outcomes for their specific runs.

The runtime uses the Python standard library, without model API calls, telemetry, or network access. Input strings, links, and commands remain data. The package is under development and has no published stable release.

## Install from a local checkout

Requires CPython 3.12, 3.13, or 3.14. The initial development baseline is Linux with Python 3.12; the full target platform matrix remains a later milestone.

From the repository root, install into your chosen virtual environment:

```sh
python -m pip install .
structural-safety --version
python -m structural_safety --help
```

Build and install a local wheel when build dependencies are available:

```sh
python -m pip install -r requirements-dev.txt
python -m build
python -m pip install dist/structural_safety_toolkit-0.1.0.dev0-py3-none-any.whl
```

These commands use local source or a local wheel. They do not require the project name to be registered on PyPI. The software is licensed under [Apache-2.0](LICENSE). This license does not extend to the referenced source papers, which are not distributed with the package.

## Validate an included example

All 18 scenarios are packaged as complete JSON resources, readable from an installed package outside the checkout. Run this Python snippet in a directory where you want to save a copy:

```python
from importlib.resources import files
from pathlib import Path

document = files("structural_safety").joinpath("examples/A.json").read_text(encoding="utf-8")
Path("A.json").write_text(document, encoding="utf-8")
```

Then validate it:

```sh
structural-safety validate A.json
python -m structural_safety validate A.json --format markdown
structural-safety validate A.json --format json --output validation.json
```

Use `-` as the input path for standard input. Reports go to standard output unless `--output` is set; operational errors go to standard error. An output path cannot be the input file. Successful validation has `validation_status="valid"` and `analysis_performed=false`.

## Python API

```python
from importlib.resources import files
from structural_safety import Limits, analyze_json, run_demo, validate_json

document = files("structural_safety").joinpath("examples/B.json").read_bytes()
validation = validate_json(document, limits=Limits())
print(validation.validation_status)
result = analyze_json(document, limits=Limits())
print(result.to_dict())
print(result.to_markdown())

demo = run_demo("B", limits=Limits())
print(demo.to_dict())
print(demo.to_markdown())
```

Pass raw JSON text or bytes, preserving duplicate-key detection. A Python dictionary is not accepted. Expected input errors and hard-limit rejection are reported in the result. Unexpected internal defects remain errors.

`analyze_json` updates model states in memory without executing deployment actions. `run_demo` accepts fixed case names, the `D`/`E`/`F` groups, or `all`, and returns a `DemoResult`. D only analyzes declarations. Other cases execute fixed requests against local targets containing synthetic bytes. Arbitrary model files and code are never executed by `demo`.

By default, `run_demo` removes its temporary run directory after embedding the observations in the result. To retain the report and synthetic target records, pass `work_dir=Path("demo-runs")` after importing `Path` from `pathlib`. Each invocation creates a fresh run subdirectory; groups give each case a separate child directory and independent analysis budget.

## Analyze an included example

```sh
structural-safety analyze A.json
python -m structural_safety analyze A.json --format markdown
structural-safety analyze A.json --format json --output analysis.json
structural-safety analyze A.json --max-states 100 --max-transition-checks 1000
```

For a B comparison, copy `examples/B.json` with the same packaged-resource snippet above and analyze `B.json`. A and B share their candidate actions and permission records. A's private publish route has no control; B declares a strict gate that rejects that same unauthorized request before its effect. The analysis report retains a modeled path and the premises used for each conclusion. Running `analyze` alone does not establish a runtime observation.

The included fixtures produce these results with the default budgets:

| Fixture | Private publish | Findings | CLI exit |
|---|---|---|---:|
| A | `feasible`, `denied`, `not_blocked_in_model` | SS001 modeled violation and SS005 control gap. | 1 |
| B | `feasible`, `denied`, `blocked_in_model` | SS005 assurance gap: control effectiveness has only model declarations. | 1 |

Both reports are `completed_for_supported_scope`. A has `violated_in_model` coverage; B has `covered_in_declared_model` coverage with runtime status `not_tested`. Internal processing and the public-object publish remain allowed and unblocked in both. B's exit 1 preserves its evidence gap even though the declared gate blocks the private request.

Search is bounded and deterministic. The CLI accepts `--max-states`, `--max-transition-checks`, `--max-scope-combinations`, `--max-clause-checks`, and `--max-findings`. A report records the effective limits and work consumed. A budget interruption produces `partial` and preserves existing findings. Unsupported operations and rules remain visible as unfinished scope.

The implemented property is `P-CONF-01`: within the declared task and snapshot, restricted object versions require valid task and source authorization to reach a recipient. The supported analysis covers its finite `read`/`transfer` routes. A new property ID or natural-language description does not create a new rule; other declared properties are reported as unsupported.

## Run the fixed scenarios

```sh
structural-safety demo A
python -m structural_safety demo B --format markdown
structural-safety demo B --format json --output demo-b.json --work-dir demo-runs
structural-safety demo C
structural-safety demo D
structural-safety demo E
structural-safety demo F
structural-safety demo all --output demo-all.json --work-dir demo-runs
```

Each executable case starts fresh and directly reads every enabled target after each operation. A/B submit the same five requests. The restricted publish request is attempted in both cases, and the driver continues with the public task after B refuses it.

| Case | Observed restricted publish | Internal task | Public task | Protocol / CLI exit |
|---|---|---|---|---|
| A | Exact restricted bytes reach the main target, an observed boundary violation. | Success. | Success. | `matched` / 0 |
| B | The control receives and refuses the request; observed external targets have no prohibited write. | Success. | Success. | `matched` / 0 |
| C | Main refuses; the alternate route writes restricted bytes while strict policy remains unchanged. | Success. | Success. | `matched` / 0 |
| D | Three analysis-only contrasts preserve behavior, declaration, and isolation evidence differences. | `not_tested`. | `not_tested`. | `matched` / 0 |
| E | E0 writes under a valid narrow release; nine one-factor variants refuse. E-unknown remains authorization-unresolved. | Success. | Success. | `matched` / 0 |
| F | F-open selects weak policy then writes; F-locked cannot select it and still attempts the refused publish. | Success. | Success. | `matched` / 0 |

Successful runs report `runtime_status="completed"`. A's exit 0 means its expected violation was demonstrated. B adds control evidence limited to the fixed requests, objects, policy, and observed local targets. The original B analysis remains `declaration_only` with runtime status `not_tested`; the demo reports its separate observations without rewriting that model result.

D is the explicit exception: its runtime, actual effects, and normal tasks remain `not_tested` or empty. Expected unresolved model facts can match the D protocol and return demo exit 0; standalone `analyze` still returns 3 for those unresolved facts. Budget truncation cannot pass by being an expected unknown.

Named subcases: `D-behavior`, `D-declaration`, `D-isolation`; `E0`, `E-version`, `E-recipient`, `E-purpose`, `E-interface`, `E-expiry`, `E-issuer`, `E-revoked`, `E-unknown`, `E-task`; `F-open`, `F-locked`. `all` expands in the table's order and each group's listed order.

The five analysis budget options listed above also apply to `demo`. The report distinguishes an expected result from a mismatch or an inconclusive comparison. All targets are local simulations. No deployment, network destination, arbitrary input configuration, or operating-system sandbox is exercised. See the [experiment protocol](docs/experiments.md) for observation limits and component separation.

## What validation establishes

Validation checks the schema version, required and unknown fields, strict types, fact states, references and endpoint types, timestamps, and input limits. It accepts explicit unknown facts and supported locations for declared unsupported semantics. It does not resolve those facts, prove a graph reachable, decide authorization, or verify that a control works.

Known values are submitted model premises. Empty evidence references remain supplied assertions. Imported event labels never establish that the toolkit directly observed an effect. See [input format](docs/input-format.md) and [semantic boundaries](docs/semantics.md).

| Exit code | Meaning |
|---:|---|
| 0 | `validate`: input structure accepted. `analyze`: supported checks completed without findings, unresolved items, or unchecked scope. `demo`: all required expectations matched. |
| 1 | `analyze`: findings were produced, with no unresolved or unfinished scope requiring exit 3. |
| 2 | Usage, input structure, schema version, or hard input limit problem. |
| 3 | `analyze`: unresolved facts, unsupported or unchecked scope, or incomplete analysis. This takes precedence over exit 1. `demo`: a necessary expectation remains inconclusive. |
| 4 | `demo`: a definite expectation mismatch. This takes precedence over an inconclusive comparison. |
| 5 | Input/output file operation failed. |
| 70 | Unexpected internal defect. |
| 130 | User interrupt. |

Zero never certifies a deployment as safe. A structurally valid `Fact.unknown` returns validation exit 0 with `analysis_performed=false`. The included A analysis returns 1 for its findings. If unresolved or unfinished scope is added, exit 3 preserves established findings alongside those limits.

## A/B fixtures and scope

A and B describe the same finite task, objects, candidate actions, technical capabilities, task grants, and source restrictions. The only intervention is the presence of the main publish control in B. The private publish request lacks authorization in both; legitimate internal processing and public-object publishing remain in both descriptions.

P1-3 introduced the separate driver, runtime control, observer, and human-fixed comparator. P1-4 extends these to C/E/F and adds D's analysis-only contrasts. The components are maintained by this project; their separation does not constitute third-party evaluation. A matching experiment establishes only its stated synthetic scope. The [experiment protocol](docs/experiments.md) records all case selections, timelines, and limitations.

## Development

```sh
python -m unittest discover -s tests -v
```

The runtime uses only the standard library. Build tools are pinned in `requirements-dev.txt` and `pyproject.toml`. Direct tests target specific input, evidence, and resource-limit failure modes.

The six implementation steps cover input foundation, the first analysis chain, direct A/B experiments, C–F cases, remaining finite operations and rules, and release usability. See [CHANGELOG](CHANGELOG.md) for implemented capabilities. The [theory source index](docs/theory-sources.md) distinguishes source ideas from software definitions.
