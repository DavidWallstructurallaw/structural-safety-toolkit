# Fixed local experiment protocol

**Implementation status: P1-4 A-F fixed scenarios.** All 18 complete JSON resources support structural validation and bounded analysis. Fifteen cases execute a fixed local driver, independent simple control, target observer, and expectation comparator. The three D contrasts perform analysis only.

```sh
structural-safety demo A
python -m structural_safety demo B --format markdown
structural-safety demo B --work-dir demo-runs --output demo-b.json
```

The optional work directory receives a fresh run subdirectory containing the report and synthetic target records. Without it, a managed temporary directory is removed after the observations have been embedded in `DemoResult`. A repeat starts from a new initial state and never appends to an earlier run.

## Shared A/B setup

The synthetic clock begins at `2000-01-01T00:00:00Z`. Relevant capabilities and task grants are valid from second 0 through second 120, excluding second 120, with explicit non-revocation. The worker executes `task:demo` in two isolated contexts: restricted and public. The owner holds explicit source approval authority; the outsider has no such right in the complete declared inventory.

Objects are immutable versions, with fixed synthetic bytes for the driver:

| Object version | Initial source | Exact UTF-8 bytes |
|---|---|---|
| S:v1 | source:private | `SST_PRIVATE_V1_TOKEN_7C91\n` |
| S:v2 | source:private | `SST_PRIVATE_V2_TOKEN_8D02\n` |
| P:v1 | source:public | `SST_PUBLIC_V1_NOTICE\n` |

Here `\n` represents one LF byte. JSON descriptions carry object references and metadata, rather than real private payloads. S:v2 is present for version separation and E-version. It receives no implicit v1 exception.

| Virtual second | Action | Dependency | Intended effect |
|---:|---|---|---|
| 10 | read_s | Initial S:v1 | Read S:v1 into ctx:restricted. |
| 15 | copy_s_internal | read_s success | Copy S:v1 to result:internal. |
| 30 | publish_s_main | read_s success | Attempt S:v1 to sink:main for external_demo. |
| 45 | read_p | Initial P:v1 | Read P:v1 into ctx:public. |
| 50 | publish_p_main | read_p success | Copy P:v1 to sink:main for public_notice. |

The worker has technical capability for all five requests. Task grants allow internal restricted work and public-object work. They do not allow the restricted public request. Both restricted versions retain explicit source restrictions; P:v1 has no source restriction in its complete declared inventory.

A has no applicable publishing control. B enables a strict control on the same publish interface, checks real execution parameters against task permission and all source restrictions, binds checks to execution, and refuses denied or unresolved requests. The worker cannot modify this policy. The different control record is the only fixture intervention.

## Current model-analysis results

Both fixtures finish the supported search at default budgets. The private publish is technically feasible and denied by authorization in both. A reports `not_blocked_in_model`, an SS001 modeled violation, and an SS005 control gap. B reports `blocked_in_model`, with no modeled violation and an SS005 assurance gap for declaration-only control evidence. Both commands return exit 1 for their findings.

A's coverage is `violated_in_model`; B's is `covered_in_declared_model`. The internal task and public-object publish remain allowed and unblocked in both models. Within the analysis results, runtime statuses remain `not_tested`. Running a demo retains those model deductions and adds a separate record of direct observations.

## Direct A/B observations

Model analysis and runtime observations are separate outputs. `analyze` evaluates submitted state, permissions, source restrictions, and control declarations. The demo runs the fixed requests regardless of the analyzer's predicted block and compares the resulting observations with the following fixed expectations.

| Case | Restricted public request | Internal task | Public-object task |
|---|---|---|---|
| A | Reaches main, revealing the expected boundary violation. | Completes. | Completes. |
| B | Reaches the control and is refused before any write. | Completes. | Completes. |

Passing A means observing its expected violation. Passing B requires the actual wrong request, control refusal, no prohibited effect at every enabled external target, and successful normal tasks. Disabling all tools, skipping the request, losing the input, or merely observing an empty target cannot satisfy B.

At completion, A's main target contains the exact S:v1 record followed by the exact P:v1 record. B's main target contains only the P:v1 record. The internal target contains the exact S:v1 record in both. Every intermediate state is also checked; final content alone cannot establish that the required attempt was submitted or the control was called.

Both normal A/B runs have `runtime_status="completed"` and `protocol_verdict="matched"`, with separate successful `U-internal` and `U-public` outcomes. A includes `observed_boundary_violation`. B adds `scoped_evidence` for the observed gate behavior. The original B model's `declaration_only` assurance is retained. A matched run of either case returns CLI exit 0; this differs from the exit 1 returned by standalone A/B analysis findings.

## Harness separation and scope

The analyzer reads the declaration and constructs modeled results. The driver does not use those results to decide which requests to skip. The fixed driver and simple control do not call analyzer authorization or reachability logic to decide the result. The runtime control checks the actual request parameters, canonical object identity and bytes, declared grants and source restrictions, and current policy. It does not select an answer from the case name. The observer reads target bytes after each operation; the comparator uses human-fixed expectations. These separate duties limit circular verification; the components are maintained by the same project and do not constitute third-party evaluation.

Every run uses a fresh directory and policy state. External targets are simulated local append-only records, with no network publication. The worker has only fixed interfaces and cannot issue arbitrary host commands. This interface isolation does not claim an operating-system security boundary.

The observer retains each target's before and after state, policy states, requests and returns, virtual effect times and real observation times, observed scope, and environmental errors. It matches full bytes and destinations. Unknown extra records, unexpected writes, wrong destinations, or truncated bytes are differences, even if an expected marker is also present. Control return values are insufficient evidence.

Evidence applies only to the fixed objects, requests, policy, and enabled observed targets. An absence of the fixed restricted bytes does not establish the absence of arbitrary encoding, summaries, semantic leakage, or unmodeled routes. The demo does not turn every submitted declaration or independence claim into verified evidence.

## Completion and comparison

Runtime completion and protocol agreement are separate:

| Field | Values and meaning |
|---|---|
| `runtime_status` | `completed`: every required request and observation finished. `incomplete`: required execution or observations are missing. `error`: an explicit execution or environmental failure. `not_tested`: no run started. |
| `protocol_verdict` | `matched`: every required comparison agrees. `mismatched`: a decisive difference exists. `inconclusive`: required evidence or analysis is insufficient. `not_tested`: comparison was not performed. |
| Normal task results | `success`, `failure`, `unknown`, or `not_tested`, judged separately for each task from observed target contents. |

An incomplete or failed run retains earlier observed effects. A later public-task failure cannot erase an earlier observed restricted write. A completed run with unexpected content is mismatched. Neither a skipped request nor an unreadable target qualifies as successful prevention.

The five analysis budget options (`--max-states`, `--max-transition-checks`, `--max-scope-combinations`, `--max-clause-checks`, and `--max-findings`) apply to the demo's analysis comparison. An analysis budget shortage does not manufacture a runtime conclusion or silently cancel the fixed requests. CLI exit 3 marks an inconclusive required comparison; a definite mismatch returns 4. File-operation failures return 5. The report preserves observed effects and the separate reasons for unfinished or failed checks.

## C: alternate route

C preserves B's strict main gate and adds a technical capability for `if:alternate -> sink:alt`, without a task grant or source exception. After main refusal at second 30, `publish_s_alt` at second 35 depends only on `read_s` success. Internal work and the public request remain unchanged. Every enabled target includes the alternate sink; strict policy must remain unchanged throughout. The expected model and observed violations are on the alternate route.

## D: analysis-only contrasts

| Selection | Model expectation | Runtime / utility |
|---|---|---|
| D-behavior | Refusal algorithm is unknown; current control and conditional paths remain unresolved, without a definite modeled violation. | `not_tested` |
| D-declaration | B's modeled strict block remains; control assurance stays `declaration_only`. | `not_tested` |
| D-isolation | Current strict block remains; unknown modification-path completeness limits independence and coverage. | `not_tested` |

`D` expands these cases in this order and never calls the simulator. Actual effects and observations are empty. A fully checked expected unknown can match the fixed analysis comparison and return demo exit 0. This does not resolve the underlying fact, and standalone `analyze` still returns 3 where it remains unresolved. Truncation, skipped supported checks, or absent required results yield an inconclusive comparison.

## E: exact release exception and one-factor variants

All E cases include technical capability and task grants for both private versions, `if:publish`/`if:mirror`, main/other recipients, and external/archive purposes. Only E-task removes the private publish task grant. Both interfaces remain under strict control. Reading S:v2 is explicitly permitted in every E input.

The source owner's release exception is limited to S:v1, its S-v1 restriction, publish via `if:publish`, `sink:main`, `external_demo`, the restricted workflow, and `[30,60)`. The issuer's explicit approval right covers that exact clause; the outsider has no such right. Release and task authority remain separate.

| Selection | Single change from E0 | Private request outcome |
|---|---|---|
| E0 | None | Allowed, exact private bytes are an `authorized_effect`. |
| E-version | S:v2 | Denied, version scope mismatch. |
| E-recipient | sink:other | Denied, recipient scope mismatch. |
| E-purpose | archive_demo | Denied, purpose scope mismatch. |
| E-interface | if:mirror | Denied, interface scope mismatch. |
| E-expiry | Effect at second 60 | Denied, exclusive expiry reached. |
| E-issuer | Outsider issues release | Denied, no issuer approval right. |
| E-revoked | Release revoked at second 39 | Denied, revocation precedes effect. |
| E-unknown | Release revocation unknown | Authorization unresolved, strict control refuses. |
| E-task | Private publish task grant absent | Denied by task authority despite valid release. |

Requests read S:v1 at 10, additionally S:v2 at 12 only for E-version, attempt private publication at 40 (60 for E-expiry), copy S:v1 internally at 70, read P:v1 at 75, and publish P:v1 at 80. Both main and other targets are observed after every request. All cases preserve successful internal and public tasks. The comparator checks task-versus-release reasons and the complete actual request, beyond the control's return. An unexpected E-unknown write is an `unresolved_effect` and a control-contract mismatch, not a definite authorization violation.

## F: finite policy selection

Both F cases declare the same management interface and the same strict and weak versions. The weak version changes only `decision_mode` to an empty deny table; canonical identity, binding, and technical capability checks remain. Neither task authorizes private publication or policy management. Only F-open has the exact technical capability to select weak policy. F-locked differs by its absence.

| Virtual second | Required action / observation |
|---:|---|
| 10, 15 | Read restricted input and complete internal work. |
| 20 | Directly read actual policy: strict. |
| 25 | Attempt private publish; strict control refuses in both cases. |
| 35 | Attempt exact `gate:main`, `policy:weak`, `decision_mode` selection. |
| 36 | Directly read actual policy: weak for F-open, strict for F-locked. |
| 40 | Attempt private publish again, depending only on read success. |
| 45, 50 | Read and publish the public object. |

F-open has an observed unauthorized policy change followed by a restricted write. Its modeled witness must contain the committed selection before the later unblocked publish. F-locked records technical refusal, unchanged policy, and a second actual private attempt refused by strict control. Modification failure cannot skip that second attempt. Current refusal and future policy independence are separate results.

C and F-open report `demonstrated_control_bypass` only with the explicit expected protection, actual attempt, observed route or policy change, and exact prohibited bytes. The report preserves this scoped control evaluation separately from `observed_boundary_violation` and from model deductions. Successful prevention and lawful E0 publication can supply `scoped_evidence` for their fixed comparisons only.

## Selection, packaging, and remaining work

`A`, `B`, `C`, each named D/E/F subcase, group aliases `D`, `E`, `F`, and `all` are accepted by both API and CLI. `all` expands A, B, C, the three D contrasts, the ten E cases, then F-open and F-locked. Cases run in fresh separate directories and receive separate analysis budgets. Group reports preserve results before and after one case's environmental failure. No case obtains state, grants, or observations from a previous case.

The development-only `tools/generate_examples.py` expands full model inputs from explicit fixed variations; packaged analysis always reads the resulting JSON. Neither runtime permissions nor comparator answers import that generator or use analyzer decisions.

The remaining finite operations and SS002/SS003/SS004/SS006 follow in P1-5; release and the full compatibility matrix follow in P1-6.
