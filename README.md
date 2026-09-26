# Structural Safety Toolkit

A local Python toolkit for describing AI agent execution topology, task authorization, information flows, control coverage, and intervention conditions.

**Latest stable release: 0.1.0. Current development version: 0.2.0.dev0 (unreleased).** The toolkit validates deployment descriptions and analyzes finite `read`, `transfer`, `derive`, `persist_write`, `persist_read`, `delegate`, `policy_update`, `revoke`, and `stop` actions with SS001 through SS006 diagnostics. It also provides 18 fixed scenarios: 15 local experiments and three analysis-only D contrasts. Analysis reports separate technical feasibility, authorization, modeled control behavior, and evidence limits. Experiment reports retain actual target observations and task outcomes for their specific runs.

The runtime uses the Python standard library, without model API calls, telemetry, or network access. Input strings, links, and commands remain data.

## Install

Requires CPython 3.12, 3.13, or 3.14. CI exercises Linux with CPython 3.12, 3.13, and 3.14, plus Windows with CPython 3.14. Linux 3.12 builds the wheel from its sdist. Each environment runs the semantic tests and checks the same wheel in a fresh installation, including README examples outside the checkout. Other operating-system and interpreter combinations are outside this matrix.

Download `structural_safety_toolkit-0.1.0-py3-none-any.whl` from the [0.1.0 release](https://github.com/DavidWallstructurallaw/structural-safety-toolkit/releases/tag/v0.1.0). From its download directory, install into your chosen virtual environment:

```sh
python -m pip install structural_safety_toolkit-0.1.0-py3-none-any.whl
structural-safety --version
```

The business templates and Claude Code importer described below require this development checkout; they are not in the 0.1.0 release wheel. From the repository root, install it:

```sh
python -m pip install .
structural-safety --version
python -m structural_safety --help
```

Build and install a local wheel when build dependencies are available:

```sh
python -m pip install -r requirements-dev.txt
python -m build
python -m pip install dist/structural_safety_toolkit-0.2.0.dev0-py3-none-any.whl
```

Release assets include the wheel and source distribution; no PyPI release is assumed. The software is licensed under [Apache-2.0](LICENSE). This license does not extend to the referenced source papers, which are not distributed with the package.

## Start with a business scenario

Three editable model pairs provide a smaller starting point than writing a complete deployment description:

| Template | Business question | Controlled comparison |
|---|---|---|
| `memory-handoff` | Can a restricted customer summary pass through shared memory into a public response? | Gate the outbound route while preserving internal handoff and public content. |
| `policy-self-modification` | Can the publishing agent weaken the policy that checks its own output? | Restrict policy changes while retaining ordinary publishing work. |
| `human-oversight` | Can an assigned reviewer intervene before a disclosure becomes irreversible? | Compare a 30-second response with a response within a 5-second window. |

```sh
structural-safety template memory-handoff --output memory-exposed.json
structural-safety template memory-handoff --variant controlled --output memory-controlled.json
structural-safety analyze memory-exposed.json --output memory-exposed-report.json
structural-safety analyze memory-controlled.json --output memory-controlled-report.json
```

`template` exports JSON and returns 0 without analysis. Both analyses above return 1: the exposed model contains a disclosure path; the controlled model blocks that path but retains its declaration-only control evidence gap. These are finite model comparisons, not additional runtime experiments. Use `get_template(name, variant="controlled")` in Python for a fresh editable dictionary, then pass `json.dumps(model)` to the existing validation and analysis APIs. See [business scenarios](docs/business-scenarios.md) for all six models, expected findings, and the facts to replace with your deployment information.

## Import a Claude Code project configuration

The first platform adapter reads the `mcpServers` declarations in a project `.mcp.json`. With no role mapping, it returns an inventory and outstanding information, with exit 3 and no model. It never starts MCP servers, runs commands or helpers, connects to URLs, or expands environment variables. Commands, arguments, URLs, and credential values are omitted from reports; server names remain visible.

Copy the packaged illustrative configuration and its role bindings:

```python
from importlib.resources import files
from pathlib import Path

for resource, destination in (
    ("claude-code-example.json", "sample-claude-mcp.json"),
    ("claude-code-bindings.json", "sample-bindings.json"),
):
    text = files("structural_safety").joinpath("integrations", resource).read_text(encoding="utf-8")
    Path(destination).write_text(text, encoding="utf-8")
```

```sh
structural-safety import-claude-code sample-claude-mcp.json --output mcp-inventory.json
structural-safety import-claude-code sample-claude-mcp.json --bindings sample-bindings.json --output mcp-import.json --model-output imported-memory.json
structural-safety analyze imported-memory.json --output imported-memory-report.json
```

For your project, substitute its configuration path and map the three `source`, `memory`, and `publish` roles to your server names. This first adapter binds only the memory-handoff scenario. Model creation returns 0 for successful import, not a safety verdict. The role assignments, task permissions, data restrictions, actions, and control behavior remain supplied scenario assumptions that you must check and edit. Only the presence of a server declaration is configuration-read evidence. The output does not discover tool schemas, prove a connection or permission, inspect other configuration scopes, or cover built-in tools. See [supported fields, mappings, and limits](docs/claude-code-import.md).

## Validate an included example

All 18 scenarios are packaged as complete JSON resources, readable from an installed package outside the checkout. Run this Python snippet in a directory where you want to save a copy:

```python
from importlib.resources import files
from pathlib import Path

for name in ("A", "D-behavior"):
    document = files("structural_safety").joinpath("examples", name + ".json").read_text(encoding="utf-8")
    Path(name + ".json").write_text(document, encoding="utf-8")
```

Then validate them:

```sh
structural-safety validate A.json
python -m structural_safety validate A.json --format markdown
structural-safety validate A.json --format json --output validation.json
structural-safety validate D-behavior.json
```

Use `-` as the input path for standard input. Reports go to standard output unless `--output` is set; operational errors go to standard error. An output path cannot be the input file. Successful validation has `validation_status="valid"` and `analysis_performed=false`. Both examples return exit 0: D-behavior's explicit unknown control behavior is valid input and remains unknown.

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
structural-safety analyze D-behavior.json
```

For a B comparison, copy `examples/B.json` with the same packaged-resource snippet above and analyze `B.json`. A and B share their candidate actions and permission records. A's private publish route has no control; B declares a strict gate that rejects that same unauthorized request before its effect. The analysis report retains a modeled path and the premises used for each conclusion. Running `analyze` alone does not establish a runtime observation.

The included fixtures produce these results with the default budgets:

| Fixture | Private publish | Findings | CLI exit |
|---|---|---|---:|
| A | `feasible`, `denied`, `not_blocked_in_model` | SS001 modeled violation and SS005 control gap. | 1 |
| B | `feasible`, `denied`, `blocked_in_model` | SS005 assurance gap: control effectiveness has only model declarations. | 1 |

Both A/B reports are `completed_for_supported_scope`. A has `violated_in_model` coverage; B has `covered_in_declared_model` coverage with runtime status `not_tested`. Internal processing and the public-object publish remain allowed and unblocked in both. B's exit 1 preserves its evidence gap even though the declared gate blocks the private request. The D-behavior analysis command returns exit 3 because its unknown control behavior remains unresolved; it still returns a report.

Search is bounded and deterministic. The CLI accepts `--max-states`, `--max-transition-checks`, `--max-scope-combinations`, `--max-clause-checks`, and `--max-findings`. A report records the effective limits and work consumed. A budget interruption produces `partial` and preserves existing findings. Explicit unsupported semantics and unknown property IDs remain visible as unfinished scope.

The implemented property is `P-CONF-01`: within the declared task and snapshot, restricted object versions require valid task and source authorization to reach a recipient. The supported analysis follows those restrictions through derivation, exact-version storage, and explicit reads into another context. Related rules check instruction authority, delegated scope, source declarations, control conditions, and specific responsibility obligations. A new property ID or natural-language description does not create a new rule; other declared properties are reported as unsupported.

| Rule | Narrow model check |
|---|---|
| SS001 | Technically feasible, unblocked effects violate task or source authorization. |
| SS002 | Explicit instruction-authority promotion or a sensitive decision lacks the required authority basis. |
| SS003 | Delegated scope exceeds complete parent clauses or valid extension authority. |
| SS004 | Declared ancestry, restrictions, or authority conflict with required source inheritance. |
| SS005 | Control coverage, parameter binding, timing, failure handling, or policy independence has a gap. |
| SS006 | A concrete responsibility obligation lacks observation, validation, competence, intervention authority, or timely response. |

Management actions bind exact typed targets. Empty data-object scope never grants arbitrary permission to delegate, revoke, or stop. Delegation, revocation, stopping, and policy selection affect only the modeled branch after their effects commit. A stop cannot undo an earlier disclosure. Known restricted sources remain in derived objects even when an output declaration omits them; unknown additional sources remain unresolved.

Optional submitted events appear as attributed `event_reports`. Claims such as `verified=true` and `reported_event_kind="effect_observed"` remain external reports. They do not cause actions to execute or convert model deductions into direct observations. See [semantic boundaries](docs/semantics.md) for complete-clause scope checks, timing rules, and evidence limits.

Three additional packaged inputs illustrate the P1-5 analysis. They are model examples, separate from the 18 fixed demo cases:

| Model input | What it demonstrates |
|---|---|
| [P1-5-state.json](src/structural_safety/examples/P1-5-state.json) | Restricted-source derivation, an exact-version storage write, a read into another context, and an SS001 publish path with the full witness. |
| [P1-5-rules.json](src/structural_safety/examples/P1-5-rules.json) | SS002 unapproved instruction authority, SS003 delegated scope expansion, and SS004 source-declaration loss, without an SS001 disclosure path. |
| [P1-5-responsibility.json](src/structural_safety/examples/P1-5-responsibility.json) | A scoped responsibility obligation with timely, target-bound stop authority; declared control evidence still has its assurance limit. |

Extract these resources from the installed package:

```python
from importlib.resources import files
from pathlib import Path

for name in ("P1-5-state", "P1-5-rules", "P1-5-responsibility"):
    text = files("structural_safety").joinpath("examples", name + ".json").read_text(encoding="utf-8")
    Path(name + ".json").write_text(text, encoding="utf-8")
```

```sh
structural-safety analyze P1-5-state.json
structural-safety analyze P1-5-rules.json
structural-safety analyze P1-5-responsibility.json
```

Each command completes supported checks and returns exit 1 for its findings under default budgets. These examples execute no deployment actions. Coverage `violation_refs` includes every modeled violation of the reported property; `disclosure_path_refs` contains only SS001 modeled disclosure paths. Thus source or delegation violations can produce `violated_in_model` without claiming a disclosure path.

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
| 0 | `template`: model exported. `import-claude-code`: model created from configuration and bindings, without analysis. `validate`: input structure accepted. `analyze`: supported checks completed without findings, unresolved items, or unchecked scope. `demo`: all required expectations matched. |
| 1 | `analyze`: findings were produced, with no unresolved or unfinished scope requiring exit 3. |
| 2 | Usage, input structure, schema version, or hard input limit problem. |
| 3 | `import-claude-code`: inventory only, scenario bindings still needed. `analyze`: unresolved facts, unsupported or unchecked scope, or incomplete analysis. This takes precedence over exit 1. `demo`: a necessary expectation remains inconclusive. |
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

The four-environment CI matrix also checks the distribution's installed API, both CLI entry points, all 18 demo scenarios, three additional finite-state model examples, six business-template models, the configuration importer, and executable README examples. These checks exercise the declared finite scope and fixed local experiments; they do not certify a real deployment. See [CHANGELOG](CHANGELOG.md) for implemented capabilities. The [theory source index](docs/theory-sources.md) distinguishes source ideas from software definitions.
