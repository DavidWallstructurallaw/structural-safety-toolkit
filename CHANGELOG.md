# Changelog

## 0.1.0.dev0: P1-3 direct A/B experiments

- Added `run_demo`, `DemoResult`, and `demo A` / `demo B` with JSON/Markdown reports and the five analysis budget options.
- Added a fixed five-request driver and a simple control that evaluates real runtime parameters without calling analyzer authorization or reachability functions.
- Added direct target and policy observations after each operation, with exact synthetic-byte comparisons against fixed expectations.
- Preserved the attempted restricted request, control returns, observed effects, and separate internal/public task results.
- Added A's observed boundary violation and B's scoped control evidence without upgrading the original model's declaration-only evidence.
- Added fresh run directories, optional retained report and target files, and embedded observations that survive default temporary-directory cleanup.
- Added direct protocol counterexamples and installed-wheel checks for both A/B demo entry points and the Python API.

The A/B experiment success criterion includes both normal tasks. A matched result for A includes its expected violation. C through F, policy updates, the remaining finite operations and four rules, the stable release, and the full compatibility matrix remain later work. The Apache-2.0 license and development version are unchanged.

## 0.1.0.dev0: P1-2 first analysis chain

- Added `analyze_json`, the `analyze` command, and JSON/Markdown analysis reports.
- Added finite `read`/`transfer` state exploration with exact object versions, execution contexts, successful dependencies, shared conditions, and timing.
- Added complete-clause technical capability and task authorization checks, source restrictions, and scoped release exceptions with explicit approval authority.
- Added SS001 modeled boundary violations and SS005 diagnostics for the supported current-policy scope.
- Kept feasibility, authorization, modeled control effects, control assurance, and check completion separate; retained witnesses and unresolved assumptions.
- Added shared analysis budgets with explicit truncation and preserved findings; unsupported operations and rules remain visible.
- Added the Apache-2.0 license and package license metadata, following the owner's selection.

At P1-2, runtime experiments and `demo` were still pending. P1-3 adds the A/B harness described above. Policy-update support and the remaining finite operations and four rules are later steps. The stable 0.1.0 release and full compatibility matrix remain pending.

## 0.1.0.dev0: P1-1 input and result foundation

- Added the Python package foundation and strict raw-JSON input contract.
- Added typed fact states, reference validation, declared unsupported items, and explicit resource limits.
- Added validation result objects, JSON/Markdown output, the `validate_json` API, and the `validate` command and module entry point.
- Added complete A/B input examples as installed package resources.
- Documented fields, semantic boundaries, theory sources, and future experiment expectations.
- Added a Linux/Python 3.12 CI workflow and a clean wheel installation check outside the source checkout.

At P1-1, the audit engine, SS001–SS006 rules, and runtime experiments were not implemented. Validation acceptance does not establish a safety conclusion. Software licensing was decided in P1-2.
