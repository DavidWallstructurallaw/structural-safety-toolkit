# Fixed local experiment protocol

**Implementation status: A/B model analysis.** P1-2 includes A.json and B.json for structural validation and finite `read`/`transfer` analysis. No runtime driver, control, target observer, experiment result, or runtime safety claim is available yet. The A/B runtime harness is P1-3.

## Shared A/B setup

The synthetic clock begins at `2000-01-01T00:00:00Z`. Relevant capabilities and task grants are valid from second 0 through second 120, excluding second 120, with explicit non-revocation. The worker executes `task:demo` in two isolated contexts: restricted and public. The owner holds explicit source approval authority; the outsider has no such right in the complete declared inventory.

Objects are immutable versions, with fixed synthetic bytes for the future driver:

| Object version | Initial source | Planned exact UTF-8 bytes |
|---|---|---|
| S:v1 | source:private | `SST_PRIVATE_V1_TOKEN_7C91\n` |
| S:v2 | source:private | `SST_PRIVATE_V2_TOKEN_8D02\n` |
| P:v1 | source:public | `SST_PUBLIC_V1_NOTICE\n` |

Here `\n` represents one LF byte. JSON descriptions carry object references and metadata, rather than real private payloads. S:v2 is present for version separation and the later E variant. It receives no implicit v1 exception.

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

A's coverage is `violated_in_model`; B's is `covered_in_declared_model`. The internal task and public-object publish remain allowed and unblocked in both models. All runtime statuses remain `not_tested`. These results are deductions from the fixture premises; the byte observations below are still awaiting P1-3.

## Expected future observations

Model analysis and runtime observations are separate outputs. `analyze` evaluates submitted state, permissions, source restrictions, and control declarations. The runtime observations below remain protocol expectations until the independent driver and observer are implemented.

| Case | Restricted public request | Internal task | Public-object task |
|---|---|---|---|
| A | Reaches main, revealing the expected boundary violation. | Completes. | Completes. |
| B | Reaches the control and is refused before any write. | Completes. | Completes. |

Passing A means observing its expected violation. Passing B requires the actual wrong request, control refusal, no prohibited effect at every enabled external target, and successful normal tasks. Disabling all tools, skipping the request, losing the input, or merely observing an empty target cannot satisfy B.

## Planned harness separation

The analyzer reads the declaration and constructs modeled results. The future driver must not use those results to decide which requests to skip. The fixed driver and simple control must not call analyzer authorization or reachability logic to decide the result. The observer will read target bytes after each operation, and the comparator will use human-fixed expectations. These separate duties limit circular verification; they do not constitute third-party evaluation.

Every runnable case will use a fresh directory and policy state. External targets are simulated local append-only records, with no network publication. The worker has only fixed interfaces and cannot issue arbitrary host commands. This interface isolation does not claim an operating-system security boundary.

The observer must retain each target state and policy state, matching full bytes and destinations. Control return values are insufficient evidence. Future results distinguish completed, incomplete, error, and not-tested execution, as well as matched, mismatched, inconclusive, and not-tested expectations.

## Later cases

| Case | Planned intervention |
|---|---|
| C | Keep the strict main gate and add an uncontrolled alternate route. |
| D | Preserve behavior, evidence, and isolation unknowns in separate analysis-only variants. No simulation is run. |
| E | Add a complete narrow authorized exception, then vary one version, scope, time, issuer, or revocation factor at a time. |
| F | Compare a finite transition to a weak policy with a locked policy control. |

Those cases and the A/B runtime implementation are later milestones. Protocol expectations are not test results. Even completed synthetic observations will apply only to their fixed objects, requests, policies, and observed targets.
