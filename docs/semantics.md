# Semantic boundaries

P1-5 provides structural validation, bounded model-state analysis for all nine declared finite operation kinds, SS001 through SS006 diagnostics, ordinary imported-event reports, and fixed A-F scenarios. D is analysis-only; the other 15 cases run local synthetic experiments. Analysis produces model deductions from submitted premises; the demo retains its direct observations separately. Adding a supported model operation does not enable execution of arbitrary user actions.

## Facts and identity

IDs are case-sensitive and belong to typed collections. A node, action, task, and object with the same text ID remain different entities. Each object version has its own ID, logical ID, and version. A permission or exception for one version does not implicitly cover another.

`known` supplies a model premise. `unknown` preserves a missing fact. `conflict` retains incompatible candidates and is unresolved for reasoning. Evidence references do not make a fact true by themselves. A known empty set means no members; an unknown set does not mean empty or universal. Scopes contain exact finite IDs, without wildcard or natural-language expansion.

## Technical ability and authorization

Technical capabilities, task grants, approval rights, and release exceptions are separate collections. Analysis matches every dimension within one complete clause, then considers alternatives across complete clauses. It cannot combine the object from one grant with the destination from another.

Task authorization also requires every applicable source restriction to hold. For each restriction, a matching original allowance or an applicable exception can satisfy it. An exception needs explicit approval authority and complete version, action, interface, recipient, purpose, workflow, and time scope. It does not supply missing technical capability or task permission, and does not relabel the object public.

Policy selection uses the additive optional `scope.policy_targets` Fact in `sst.model/0.1`. Each target binds an exact control ID, one declared policy version belonging to that control, and an explicit field set. Management queries have no data-object version, require known empty `objects`, and require all changed fields within one matching target in one complete scope clause. Missing or empty policy targets grant nothing; field sets cannot be spliced across targets or grants. Technical capability, task grant, and the issuer's approval scope use the same typed target, while retaining all other scope and validity dimensions. A release exception does not authorize policy management.

The `select_policy` effect only chooses a declared policy version. Every changed sensitive field must appear in the effect and in the control's modifiable fields. It cannot change grants, restrictions, canonical data, observations, or expected answers. A successful transition changes the branch-local policy; blocked or technically impossible selections retain the previous state. Conditional changes retain their assumptions, and earlier conditional checks retain their historical policy state. The selected policy governs subsequent effects, while current strict refusal remains valid before the selection. Management diagnostics use SS005, with no invented data object or SS001 data leak for the selection itself.

A control covering management requests must check `policy_target` (the exact control/version/fields tuple), in place of the data-only `object_version` requirement. The other required parameters and bound, before-effect checks still apply. A data gate's parameter declaration cannot by itself prove a complete management check. `policy_target` is the corresponding additive `checked_parameters` value in this development schema.

Activation, revocation, and stopping use the additive optional `scope.management_targets` Fact. Each target is a typed collection/ID pair. Activation includes every capability and task grant in that atomic effect; revocation names one authorization record; stopping names one action, actor, or interface. Its query has `object_version_id=null`, recipient `not_applicable`, known empty scope `objects`, and all requested targets within one complete scope clause. Missing or empty targets grant nothing. A same-named record in another collection does not match, and separate grants cannot be joined to cover different targets. Capability, task permission, and approval authority remain independent checks.

A control covering these requests must check `management_targets` in place of data-only `object_version`, alongside its other binding, timing, and parameter requirements. A release exception cannot supply missing management authority. Policy selection retains its separate `policy_target` check.

Validity intervals include the start and exclude expiry. Unbounded validity and revocation state require explicit declarations. Neither missing expiry nor missing revocation evidence grants indefinite permission.

## Objects and candidate actions

Actions describe finite candidates, rather than proof of past execution. Data-flow, execution, persistence, capability, and policy-change projections come from their canonical records. Only supported supplementary relation kinds are independently entered. An untyped graph path cannot replace task, workflow, context, time, and state checks.

Copying retains the object version. A fixed public object can be copied from an isolated public context while the same actor separately reads a restricted object. Unknown ancestry remains unknown; a submitted label cannot establish complete ancestry or permission.

Derivation creates a declared candidate version only after its producing effect commits. Its sources include the known explicit inputs and sources visible in the generation context. Each ancestor's known restrictions continues to apply. The known ancestor set and its completeness are separate: unknown additional context prevents an unsupported allowance while preserving a definite refusal from a known restriction. An output's omitted parent, public label, or weaker restriction declaration cannot delete known inherited limits. SS004 records the declaration discrepancy separately from any SS001 path.

For snapshot-initial derived versions, declared parents and their restrictions remain part of source analysis even when production predates the candidate action list. Source consistency checks keep uncertainty about undeclared ancestry explicit. Different restrictions combine conjunctively; a release for one source cannot release another source. Instruction authority also requires its own scoped approval basis.

Storage writes and reads preserve the exact version. A read into another execution context requires an explicit store input and receiving context output, with technical ability and task scope evaluated for that action. A shared store name does not create visibility, change object identity, or remove source restrictions. Witnesses preserve the producing, writing, reading, and later transfer effects needed for a reachable path.

One action can have several atomic effects. They require separate authorization and control decisions; a shared group does not promise transaction atomicity. A blocked effect does not produce output or satisfy a successful dependency. A permission denial alone does not physically block execution.

## Delegation, revocation, and stopping

A delegation effect activates only its explicitly referenced finite authorization records. The linked relation provides the parent/child actor and task mapping. SS003 compares child combinations against complete valid parent clauses after applying that mapping. It preserves correlations between object, operation, recipient, interface, purpose, workflow, conditions, and validity. Matching fragments from different parents cannot create a nonexistent parent grant. A permitted extension requires explicit approval authority covering the added scope; permission to perform the management action alone does not prove that scope containment holds.

Finite scope combinations are checked lazily under the shared `max_scope_combinations` budget. Validity coverage uses exact interval endpoints rather than sampling seconds. A definite uncovered combination can establish an SS003 counterexample when the parent inventory is complete. Unknown scope or approval facts remain unresolved; budget exhaustion retains established counterexamples and marks uncompleted work. A scope expansion can be a modeled violation even if no child data operation executes. Activating a task grant does not automatically create a technical capability.

Authorization activation and revocation belong to each search branch. A revoked capability, task grant, approval right, or release exception cannot support a later effect at or after the revocation time. Other independently valid records remain available. Unknown timing or conditional activation retains its assumptions instead of producing an unconditional permission.

Stopping records an exact target and effective time. A stopped action, actor, or interface suppresses applicable subsequent effects. The state remains stopped because the finite language has no restart operation. Stopping after a disclosure preserves that earlier effect; uncertain order remains conditional. Search keeps active/revoked and stopped/unstopped branches distinct.

## Control and observation

Analysis keeps these questions separate:

| Question | Result axis |
|---|---|
| Can the candidate execute under the modeled conditions? | `feasibility` |
| Is its complete action tuple authorized? | `authorization` |
| Does the current policy block the effect? | `control_effect` |
| What supports actual control efficacy? | `control_assurance` |
| Was the obligation fully checked? | `check_status` |

A declared policy may establish a modeled current block, subject to its premises. It does not establish runtime efficacy. Future policy mutability affects independence and coverage; it does not erase a known current rejection. A successful explicit transition to a weak policy is needed before reasoning about that later policy state.

`supplied_assertion`, `configuration_read`, `model_deduction`, `runtime_observation`, and `external_report` describe provenance without an automatic confidence ordering. Evidence also needs matching scope and applicability. Imported records claiming an observed effect remain reported records. A proposal does not imply an attempt, a return value does not imply a write, and an empty target without an actual attempt does not prove prevention.

Optional `events` become `event_reports` with their reported kind, run, action, objects, observer, environment, times, and submitted claims. They preserve external-report provenance. An imported `effect_observed`, `verified=true`, or `claimed_origin="tool_run"` does not produce toolkit observation evidence, an observed-violation classification, or a state transition. These reports do not erase untried candidate routes or establish that an entire deployment inventory is complete. Reimporting an old demo record through this ordinary interface restores the same reported-evidence boundary.

The A/B demo submits fixed requests through a separate simple control and reads the actual local targets after every operation. Its comparator uses fixed expectations rather than analyzer-generated answers. A match for A includes an observed boundary violation. A match for B requires the unauthorized request to reach the control, a refusal, no prohibited write at every enabled external target, and both legitimate tasks to succeed. B's resulting `scoped_evidence` applies only to that run; it leaves the input declaration and standalone analysis evidence unchanged.

These observations concern exact synthetic bytes, fixed operations, and local append-only targets. They do not establish control of arbitrary encodings or semantic leakage, other routes or environments, or an operating-system security boundary. A later failure preserves earlier sufficiently observed effects. The [experiment protocol](experiments.md) describes completion and comparison status separately.

## Unknown and completion

For three-valued reasoning, a definite false necessary condition makes an AND false. All necessary conditions must be true to establish true. One independent complete true alternative can establish an OR true; a false result across alternatives requires a complete relevant inventory. Remaining cases stay unknown.

An unknown fact can be structurally valid and fully processed while its conclusion remains unresolved. Unsupported semantics and unfinished analysis also remain visible. Input hard-limit rejection is distinct from analysis search-budget truncation. A lack of findings does not establish complete coverage.

State search preserves exact object locations, source and context visibility, effective authorizations, revocations, stopped targets, policy versions, successful dependencies, shared conditions, and timing. It records atomic effect success separately from whole-action success. Equal node names cannot join otherwise incompatible paths. A conditional successor keeps its unresolved premises; it cannot become a definite violation merely by reaching another action.

The finite search explores stable action/effect order and records representative witnesses before merging equivalent successor states. State, transition, scope-combination, clause, and finding budgets are global to one analysis. A limit reached with work still pending produces `partial`; conclusions already established remain in the report. Representative witnesses are not a count of all possible paths.

## Rule scope

`P-CONF-01` is the implemented property ID for the restricted-information boundary and its related source, authority, and control conditions. The analyzer evaluates its supported finite transitions within the supplied task and snapshot; SS002, SS003, and SS004 run when that property is declared. SS006 checks explicit responsibility obligations and retains each obligation's own property reference. A property description remains input text. Declaring another property ID does not define a new property checker, and reports retain that property as unsupported scope even when its explicit responsibility conditions can be evaluated.

SS002 checks explicit task or policy authority claims and relevant sensitive decision slots. Reading, summarizing, storing, or returning lower-authority content does not grant it action or policy authority. A semantic-influence relation identifies a possible decision influence; it neither supplies technical capability nor proves that a prompt injection succeeded. Definite unsupported authority promotion, uncertainty about approval, and a mere influence relationship retain their different conclusions.

SS006 evaluates concrete supplied responsibility obligations. It checks the responsible principal, matching observation and intervention relations, an inspectable basis, verification reliability, reviewer capability, appropriate stop authority and target, and response timing. A name, title, reviewer label, or observation channel cannot supply missing intervention authority. Each missing or unresolved condition remains visible even if another condition is satisfied.

Responsibility timing uses one explicit trigger. The input can provide a single end-to-end response interval, or separate detection, escalation, decision, and stop-effect intervals with explicit sequential and nonoverlapping claims. These are alternative representations. Separate phases are summed only when the required ordering and nonoverlap are established; unknown phases remain unresolved and an end-to-end duration is not counted twice.

Timely intervention requires the response upper bound to be strictly less than the consequence-window lower bound. A response lower bound at or beyond the consequence-window upper bound is too late; overlapping or unknown bounds remain unresolved. Thus an upper response bound of 8 seconds before a lower consequence bound of 10 seconds satisfies timing, while a lower response bound of 12 seconds against an upper consequence bound of 10 seconds does not. Even timely response does not establish the separate competence, validation, or stop-authority conditions. These are model interval calculations, with no experiment on real human response.

All six narrow rules are implemented within those limits:

| Rule | Subject | Current status |
|---|---|---|
| SS001 | A technically feasible unblocked path violates task or source-use authorization. | Implemented for supported finite data effects, retaining derivation and persistence witnesses. |
| SS002 | Lower-authority content affects a sensitive decision or acquires unapproved authority. | Explicit authority and sensitive-slot checks; influence alone does not prove execution or an attack. |
| SS003 | Delegated scope exceeds complete parent clauses or valid extension authority. | Finite complete-clause containment, explicit actor/task mapping, and validity coverage. |
| SS004 | Claimed lineage, restrictions, or authority fail to retain required source semantics. | Source-declaration consistency with preserved known inheritance and explicit unknown ancestry. |
| SS005 | Control coverage, timing, parameter binding, failure handling, or policy isolation has a gap. | Implemented for current declared policies and finite exact-target policy selection; reachable sensitive changes limit independence. |
| SS006 | A concrete responsibility, observation, validation, competence, stop-right, or timing condition is missing or unresolved. | Specific obligation conditions and end-to-end or sequential response intervals. |

Coverage reports `violated_in_model` when any rule establishes a modeled violation for that task and property. `violation_refs` retains all those findings; `disclosure_path_refs` retains only SS001 paths. An unapproved delegation or inconsistent source declaration can establish a modeled violation without establishing disclosure or execution.

There is no total safety score, legal liability finding, personnel qualification certification, or claim that every natural-language leakage channel is modeled.
