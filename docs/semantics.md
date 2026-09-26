# Semantic boundaries

P1-2 implements structural validation, bounded model-state analysis for `read`/`transfer`, and SS001/SS005 diagnostics. This document distinguishes that implemented subset from the remaining planned semantics. Analysis is local and produces model deductions from submitted premises.

## Facts and identity

IDs are case-sensitive and belong to typed collections. A node, action, task, and object with the same text ID remain different entities. Each object version has its own ID, logical ID, and version. A permission or exception for one version does not implicitly cover another.

`known` supplies a model premise. `unknown` preserves a missing fact. `conflict` retains incompatible candidates and is unresolved for reasoning. Evidence references do not make a fact true by themselves. A known empty set means no members; an unknown set does not mean empty or universal. Scopes contain exact finite IDs, without wildcard or natural-language expansion.

## Technical ability and authorization

Technical capabilities, task grants, approval rights, and release exceptions are separate collections. Analysis matches every dimension within one complete clause, then considers alternatives across complete clauses. It cannot combine the object from one grant with the destination from another.

Task authorization also requires every applicable source restriction to hold. For each restriction, a matching original allowance or an applicable exception can satisfy it. An exception needs explicit approval authority and complete version, action, interface, recipient, purpose, workflow, and time scope. It does not supply missing technical capability or task permission, and does not relabel the object public.

Administrative effects (`select_policy`, `revoke`, `stop`, and `activate_authorizations`) retain exact typed targets and undergo structural reference checks. The mapping from those targets into authorization scope, including `scope.objects`, remains an unresolved implementation contract. An empty `objects` set cannot mean permission over every administrative target, and structural acceptance does not establish administrative authorization. P1-2 reports these effects as unsupported and leaves affected checks partial or not checked. Before policy updates in P1-4 and the remaining administrative effects in P1-5 are analyzed, their target-binding contract and direct counterexamples must be implemented; any necessary schema adjustment must be recorded explicitly.

Validity intervals include the start and exclude expiry. Unbounded validity and revocation state require explicit declarations. Neither missing expiry nor missing revocation evidence grants indefinite permission.

## Objects and candidate actions

Actions describe finite candidates, rather than proof of past execution. Data-flow, execution, persistence, capability, and policy-change projections come from their canonical records. Only supported supplementary relation kinds are independently entered. An untyped graph path cannot replace task, workflow, context, time, and state checks.

Copying retains the object version. A fixed public object can be copied from an isolated public context while the same actor separately reads a restricted object. Unknown ancestry remains unknown; a submitted label cannot establish complete ancestry or permission.

Derivation and persistence are later implementation steps. Their contract requires derived objects to retain known source restrictions from explicit inputs and the generation context; a submitted output label must not delete known restricted ancestry. P1-2 does not simulate these effects as identity operations.

For already-existing derived versions, P1-2 follows declared known parents and inherits their known restrictions during SS001 authorization checks. Unknown or incomplete ancestry prevents an unsupported permission conclusion. The separate SS004 check for whether a static derived-source declaration faithfully retained its sources and restrictions remains `not_checked`; inherited SS001 restrictions do not establish that consistency check.

One action can have several atomic effects. They require separate authorization and control decisions; a shared group does not promise transaction atomicity. A blocked effect does not produce output or satisfy a successful dependency. A permission denial alone does not physically block execution.

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

## Unknown and completion

For three-valued reasoning, a definite false necessary condition makes an AND false. All necessary conditions must be true to establish true. One independent complete true alternative can establish an OR true; a false result across alternatives requires a complete relevant inventory. Remaining cases stay unknown.

An unknown fact can be structurally valid and fully processed while its conclusion remains unresolved. Unsupported semantics and unfinished analysis also remain visible. Input hard-limit rejection is distinct from analysis search-budget truncation. A lack of findings does not establish complete coverage.

State search preserves exact object locations, execution contexts, successful dependencies, shared conditions, and timing. It records atomic effect success separately from whole-action success. Equal node names cannot join otherwise incompatible paths. A conditional successor keeps its unresolved premises; it cannot become a definite violation merely by reaching another action.

The finite search explores stable action/effect order and records representative witnesses before merging equivalent successor states. State, transition, clause, and finding budgets are global to one analysis. A limit reached with work still pending produces `partial`; conclusions already established remain in the report. Representative witnesses are not a count of all possible paths.

## Rule scope

`P-CONF-01` is the implemented property ID for the initial restricted-information boundary. P1-2 evaluates its supported `read`/`transfer` paths within the supplied task and snapshot. A property description remains input text. Declaring another property ID does not define executable semantics, and reports retain that property as unsupported scope.

Responsibility timing uses one explicit trigger. The input can provide a single end-to-end response interval, or separate detection, escalation, decision, and stop-effect intervals with explicit sequential and nonoverlapping claims. These are alternative representations. Later timing analysis may add the separate intervals only when the required ordering and nonoverlap conditions are established; it must preserve missing phase information and avoid double counting an end-to-end duration.

The planned timely-intervention condition requires the response upper bound to be strictly less than the consequence-window lower bound. A response lower bound at or beyond the consequence-window upper bound is too late; overlapping or unknown bounds remain unresolved. Even a timely response does not establish the separate competence, validation, or stop-authority conditions. P1-2 checks these input shapes and duration bounds, without evaluating this SS006 timing condition.

Only SS001 and the current-state SS005 checks are implemented in P1-2. Policy-transition effects and the other four rules remain explicit later scope:

| Rule | Subject | P1-2 status |
|---|---|---|
| SS001 | A technically feasible unblocked path violates task or source-use authorization. | Implemented for supported `read`/`transfer` effects. |
| SS002 | Lower-authority content affects a sensitive decision or acquires unapproved authority. | Not implemented. |
| SS003 | Delegated scope exceeds complete parent clauses or valid extension authority. | Not implemented. |
| SS004 | Claimed lineage, restrictions, or authority fail to retain required source semantics. | Not implemented. |
| SS005 | Control coverage, timing, parameter binding, failure handling, or policy isolation has a gap. | Implemented for current declared policies; policy changes remain unsupported. |
| SS006 | A concrete responsibility, observation, validation, competence, stop-right, or timing condition is missing or unresolved. | Not implemented. |

There is no total safety score, legal liability finding, personnel qualification certification, or claim that every natural-language leakage channel is modeled.
