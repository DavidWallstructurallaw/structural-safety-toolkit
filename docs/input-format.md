# Input format: sst.model/0.1

The executable contract is the strict Python validator, with its field descriptors in [schema.py](../src/structural_safety/schema.py). This document lists every field and shape. The analyzer evaluates `read` and `transfer` with SS001/SS005. Parsing other valid fields does not mean their analysis semantics have been implemented; unsupported effects and rules remain visible in analysis reports. The fixed local A/B demo is a separate execution interface and does not execute arbitrary submitted JSON models.

Read the complete [A fixture](../src/structural_safety/examples/A.json) or [B fixture](../src/structural_safety/examples/B.json) for a working input. All top-level fields except `events` are required; empty lists are allowed where their minimum is zero. Every object is closed to unknown fields, including nested objects and facts. There is no catch-all metadata or custom-code field.

## Primitive types and facts

- `string` is a nonempty, non-whitespace string. IDs are case-sensitive. `*` and `not_applicable` are reserved and cannot identify records or ports.
- `boolean` accepts JSON true or false. `integer` excludes booleans. Numbers must be finite; NaN, Infinity, and JSON overflow to infinity are invalid.
- `timestamp` is a valid UTC timestamp with seconds and `Z` or `+00:00`; a validity interval must start strictly before its finite expiry. It includes the start and excludes expiry. `unbounded` is permitted only where listed.
- `Ref<C>` is a string ID from the named collection; allowed node kinds appear in parentheses. Same text in another collection cannot satisfy the reference. `TypedRef` explicitly carries its collection and ID.
- `Set<T>` uses a JSON array with distinct members. `List<T>` preserves records and may contain repeated values unless another identity rule forbids them. Their minimum sizes are stated below.
- `Fact<T>` has exactly one of the following three shapes. Every `evidence_refs` is a set of IDs from `evidence` and is required even when empty.

```json
{"state":"known","value":true,"evidence_refs":[]}
```

```json
{"state":"unknown","reason":"The configuration has not established this fact.","evidence_refs":[]}
```

```json
{"state":"conflict","candidates":[{"value":true,"evidence_refs":[]},{"value":false,"evidence_refs":[]}],"evidence_refs":[]}
```

Conflict requires at least two distinct values of the field's declared T; each candidate has its own evidence references. Unknown has no `value`, and known has no unknown `reason`. The shapes are not interchangeable with null. `known` remains a submitted premise; empty evidence is treated as a supplied assertion, never a direct observation. A known empty set and an unknown set have different meanings.

Conflict distinctness uses the field's semantic type: reordering a set does not make another candidate, UTC `Z` and `+00:00` represent the same instant, and numeric `1` and `1.0` represent the same number. Boolean true remains distinct from number 1. References inside every conflict candidate still require valid targets of the right type.

`not_applicable` is allowed only by an explicitly listed union/reference. It cannot stand in for a real transfer recipient. No permissions or unrestricted scopes are inferred from an omitted field.

## Canonical records and cross-record constraints

- Nodes represent components; object versions represent data or policy resources; actions represent finite candidates. `context` declares task, workflow, interface, operation, purpose, property, completeness, and initial-state inventories.
- IDs are unique within each typed collection. An object `(logical_id, version)` identifies exactly one object version. Port IDs are unique across the combined input and output ports of their action; effect IDs are unique within their action. Policy version IDs are unique within their control, and a selected policy must belong to that control.
- Each `(task_id, collection)` pair has at most one `context.completeness` record. Express conflicting completeness claims in that record's Fact, rather than duplicate records. Initial condition keys are also unique.
- A context belongs to one actor, task, and workflow. A location with a context must be held by that context's actor. Candidate-produced objects have no initial locations or initial visibility and must name exactly one matching produce effect of their producer action. Multiple produce effects for the same immutable version are invalid, including effects within the same action. A snapshot-initial version cannot also have a current candidate producer.
- Actions map their operation through `context.operation_definitions` and an interface that supports it. Effects reference input and output ports in the corresponding direction of the same action. Transfer uses one input and preserves the version; every output has exactly one producing or delivering effect. A candidate can be syntactically valid while it is unreachable or unauthorized.
- Task grants, capabilities, approval rights, and release exceptions have separate typed references. A scope clause matches its dimensions together; it cannot borrow individual dimensions from unrelated clauses. `approval_refs` supplies explicit authority references and does not prove authenticity.
- Validity starts strictly before finite expiry; a duration's lower bound may equal its upper bound. A known revocation with `revoked=true` requires a UTC `at` time; `revoked=false` requires `at="not_applicable"`. If the revocation time is unknown, use an unknown Fact for the entire revocation value.
- `eq` conditions have a scalar value; `in` conditions have a nonempty list. Conditions are conjunctive and use finite declared keys/values, without an expression language.
- `production.kind=candidate_action` requires `action_id`. Historical and unknown production cannot name a current producer; unknown production requires `reason`.
- Only credential nodes may have `permission_refs`. They store references to capabilities and never credential secrets.
- Unsupported operations require `unsupported_reason`. Other unsupported material belongs in `context.unsupported_items`, with `reason` and affected typed references. Unknown impact is expressed using a Fact unknown. Misspelled ordinary fields are invalid.
- Supplementary relations accept only semantic influence, delegation, observation, or intervention. Data flow, execution, persistence, capability, and policy-change projections come from canonical records. Relation endpoint kinds, action references, local port references, and responsibility observation/intervention relation kinds are checked.
- Each `activate_authorizations` effect must be covered by a delegation relation linked to the same action, naming the activated capability and grant references and the parent/child identity mapping. The relation's parent identity must match its delegate action. Structural validation does not decide whether the delegated authorization scope is permitted.
- Ordinary events always carry `reported_event_kind`. Optional `verified` and `claimed_origin` are claims by the submitter and do not establish direct toolkit observation. Omitting `events` means no event submission; an empty event list is an explicit empty submission.
- Empty `obligations` is legal. Later analysis derives obligations from other canonical records; validation does not conclude that there are none.
- `responsibility.response` is a Fact whose value is either one end-to-end duration or a `response_phases` record. The phase form requires detection, escalation, decision, and stop-effect durations plus explicit `sequential` and `nonoverlapping` Facts. Both forms use `responsibility.trigger` as their time origin. They cannot be mixed in one value or counted twice. Unknown phase values and false/unknown ordering assertions are structurally valid; validation does not sum them or infer timely intervention.

Cycles among candidate actions, mutually exclusive conditions, absent technical capability, expired or excessive grants, and omitted source restrictions can all be structurally valid. Their reachability or authorization consequences belong to semantic analysis, so validation does not reject them merely to avoid an adverse result.

## Input limits

The `limits` object is required and may be empty. Missing fields use defaults. Each supplied field must be a positive integer, excluding booleans. The effective value is the smaller of the input request and caller policy; the input cannot raise the caller's cap.

| Field | Default | Scope |
|---|---:|---|
| max_input_bytes | 2097152 | Original UTF-8 input bytes. |
| max_depth | 32 | Root container depth is 1. |
| max_records | 10000 | Model records, ports, clauses, conditions, evidence, and events before deduplication. |
| max_actions | 128 | Both candidate action count and normalized atomic execution item count. |
| max_states | 10000 | Shared analysis state budget, including the initial state. |
| max_transition_checks | 100000 | Shared atomic candidate-transition budget. |
| max_scope_combinations | 20000 | Scope-comparison budget; reserved for later scope-containment checks. |
| max_clause_checks | 1000000 | Shared complete clause-matching budget. |
| max_findings | 1000 | Distinct-finding retention budget. |

The first four are input hard limits. `validate` checks the budget fields without starting a search. `analyze` enforces the applicable budgets across the full analysis, without resetting them per action or rule. Caller hard limits apply before parsing; lower limits requested by a parsed input also apply. A hard-limit rejection returns `resource_rejected`. Search-budget truncation returns `partial` and preserves established findings and unfinished scope.

## Result and error boundary

Validation returns `sst.validation/0.1`, with `validation_status` of `valid`, `input_invalid`, `unsupported_schema`, or `resource_rejected`, location diagnostics, declared unsupported items, effective limits, and `analysis_performed=false`. Locations use JSON Pointer paths. Diagnostics identify errors without echoing an entire input document. Legal unknowns and explicit unsupported declarations can be structurally valid.

Analysis returns `sst.report/0.1`. An invalid input retains its input error status and has `analysis_performed=false`. After analysis starts, `analysis_status` is `completed_for_supported_scope` or `partial`. Completion can coexist with unresolved facts that have been fully processed; it does not imply authorization or control coverage.

| Analysis field | Meaning |
|---|---|
| `scope` | Snapshot ID, as-of time, root task, declared scope, and declared known limits. |
| `findings` | Retained SS001/SS005 findings with their model premises and representative witnesses. |
| `unresolved_items` | Facts or conclusions that remain unresolved. |
| `obligations` | Per-obligation outcomes and check completion. |
| `input_completeness` | Declared inventory completeness and its evidence limits. |
| `supported_capabilities` | Capabilities implemented by this analyzer version. |
| `unsupported_items` | Unimplemented operations, rules, properties, or explicit unsupported semantics and their affected scope. |
| `effective_limits`, `budget_usage`, `truncation` | Effective resource policy, work consumed, and any stopped work. |
| `action_results` | Candidate effect judgments, with feasibility, authorization, and modeled control decisions kept separate. |
| `coverage` | Coverage conclusions for supported scope, retaining incomplete or unresolved checks. |

The analyzer implements property `P-CONF-01` for its finite `read`/`transfer` scope. Other property labels and descriptions remain structurally valid but do not acquire executable rules from their text.

Duplicate JSON keys, dangling references, unsupported ordinary fields, invalid timestamps, wrong endpoint types, boolean counts, and nonstandard numbers are rejected. An unrecognized input schema version receives `unsupported_schema`. No JSON or Markdown report is a safety certificate.

## Complete field reference

Named types below resolve to their matching section. Required means the field must be present; optional fields can still have conditional requirements listed above. Arrays with minimum 0 can be empty. Enumeration values are exact strings. Validation also applies the cross-record constraints above.

### root

| Field | Required | Type / allowed values |
|---|---|---|
| `context` | yes | [context](#context) |
| `nodes` | yes | List&lt;[node](#node)&gt;; minimum 0 |
| `execution_contexts` | yes | List&lt;[execution_context](#execution-context)&gt;; minimum 0 |
| `object_versions` | yes | List&lt;[object_version](#object-version)&gt;; minimum 0 |
| `actions` | yes | List&lt;[action](#action)&gt;; minimum 0 |
| `relations` | yes | List&lt;[relation](#relation)&gt;; minimum 0 |
| `authorization` | yes | closed object: `capabilities`, `task_grants`, `approval_rights`, `release_exceptions` |
| `restrictions` | yes | List&lt;[restriction](#restriction)&gt;; minimum 0 |
| `controls` | yes | List&lt;[control](#control)&gt;; minimum 0 |
| `obligations` | yes | List&lt;[obligation](#obligation)&gt;; minimum 0 |
| `evidence` | yes | List&lt;[evidence](#evidence)&gt;; minimum 0 |
| `events` | no | List&lt;[event](#event)&gt;; minimum 0 |
| `limits` | yes | [limits](#limits) |

### authorization

| Field | Required | Type / allowed values |
|---|---|---|
| `capabilities` | yes | List&lt;[capability](#capability)&gt;; minimum 0 |
| `task_grants` | yes | List&lt;[grant](#grant)&gt;; minimum 0 |
| `approval_rights` | yes | List&lt;[approval](#approval)&gt;; minimum 0 |
| `release_exceptions` | yes | List&lt;[release](#release)&gt;; minimum 0 |

### typed-ref

| Field | Required | Type / allowed values |
|---|---|---|
| `collection` | yes | `nodes`, `execution_contexts`, `object_versions`, `actions`, `tasks`, `workflows`, `interfaces`, `operations`, `purposes`, `properties`, `controls`, `capabilities`, `task_grants`, `approval_rights`, `release_exceptions`, `restrictions`, `relations`, `obligations`, `evidence`, `events` |
| `id` | yes | string |

### validity

| Field | Required | Type / allowed values |
|---|---|---|
| `not_before` | yes | timestamp |
| `expires_at` | yes | timestamp OR `unbounded` |

### revocation

| Field | Required | Type / allowed values |
|---|---|---|
| `revoked` | yes | boolean |
| `at` | yes | timestamp OR `not_applicable` |

### duration

| Field | Required | Type / allowed values |
|---|---|---|
| `lower` | yes | number; minimum 0 |
| `upper` | yes | number; minimum 0 OR `unbounded` |

### condition

| Field | Required | Type / allowed values |
|---|---|---|
| `key` | yes | string |
| `operator` | yes | `eq`, `in` |
| `value` | yes | string OR number OR boolean OR Set&lt;string OR number OR boolean&gt;; minimum 1 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### scope

| Field | Required | Type / allowed values |
|---|---|---|
| `tasks` | yes | Fact&lt;Set&lt;Ref&lt;tasks&gt;&gt;; minimum 0&gt; |
| `actors` | yes | Fact&lt;Set&lt;Ref&lt;nodes&gt; (principal, executor, service)&gt;; minimum 0&gt; |
| `objects` | yes | Fact&lt;Set&lt;Ref&lt;object_versions&gt;&gt;; minimum 0&gt; |
| `operations` | yes | Fact&lt;Set&lt;Ref&lt;operations&gt;&gt;; minimum 0&gt; |
| `interfaces` | yes | Fact&lt;Set&lt;Ref&lt;interfaces&gt;&gt;; minimum 0&gt; |
| `recipients` | yes | Fact&lt;Set&lt;Ref&lt;nodes&gt; (principal, executor, service, resource, tool, store, control) or `not_applicable`&gt;; minimum 0&gt; |
| `purposes` | yes | Fact&lt;Set&lt;Ref&lt;purposes&gt;&gt;; minimum 0&gt; |
| `workflows` | yes | Fact&lt;Set&lt;Ref&lt;workflows&gt;&gt;; minimum 0&gt; |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |

### task

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `parent_task` | yes | Fact&lt;Ref&lt;tasks&gt; or `not_applicable`&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### workflow

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `task_id` | yes | Ref&lt;tasks&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### interface

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `node_id` | yes | Ref&lt;nodes&gt; (principal, executor, service, tool, store, resource, control) |
| `operation_ids` | yes | Set&lt;Ref&lt;operations&gt;&gt;; minimum 1 |
| `credential_required` | yes | Fact&lt;boolean&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### operation

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `semantic_kind` | yes | `read`, `transfer`, `derive`, `persist_write`, `persist_read`, `delegate`, `policy_update`, `revoke`, `stop`, `unsupported` |
| `unsupported_reason` | no | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### label

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `description` | yes | string |

### completeness

| Field | Required | Type / allowed values |
|---|---|---|
| `task_id` | yes | Ref&lt;tasks&gt; |
| `collection` | yes | `nodes`, `actions`, `authorization`, `capabilities`, `task_grants`, `approval_rights`, `release_exceptions`, `sources`, `restrictions`, `controls`, `policy_change_paths`, `relations`, `execution_contexts`, `object_versions` |
| `complete` | yes | Fact&lt;boolean&gt; |

### unsupported

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `reason` | yes | string |
| `affected_refs` | yes | Fact&lt;Set&lt;[typed_ref](#typed-ref)&gt;; minimum 0&gt; |

### stopped

| Field | Required | Type / allowed values |
|---|---|---|
| `target` | yes | [typed_ref](#typed-ref) |
| `effective_at` | yes | Fact&lt;timestamp&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### condition-binding

| Field | Required | Type / allowed values |
|---|---|---|
| `key` | yes | string |
| `value` | yes | Fact&lt;string OR number OR boolean&gt; |

### context

| Field | Required | Type / allowed values |
|---|---|---|
| `schema_version` | yes | `sst.model/0.1` |
| `snapshot_id` | yes | string |
| `as_of` | yes | timestamp |
| `tasks` | yes | List&lt;[task](#task)&gt;; minimum 1 |
| `root_task` | yes | Ref&lt;tasks&gt; |
| `workflows` | yes | List&lt;[workflow](#workflow)&gt;; minimum 0 |
| `interfaces` | yes | List&lt;[interface](#interface)&gt;; minimum 0 |
| `operation_definitions` | yes | List&lt;[operation](#operation)&gt;; minimum 0 |
| `purposes` | yes | List&lt;[label](#label)&gt;; minimum 0 |
| `properties` | yes | List&lt;[label](#label)&gt;; minimum 0 |
| `declared_scope` | yes | string |
| `known_limits` | yes | List&lt;string&gt;; minimum 0 |
| `completeness` | yes | List&lt;[completeness](#completeness)&gt;; minimum 0 |
| `unsupported_items` | yes | List&lt;[unsupported](#unsupported)&gt;; minimum 0 |
| `initial_conditions` | yes | List&lt;[condition_binding](#condition-binding)&gt;; minimum 0 |
| `stopped_targets` | yes | List&lt;[stopped](#stopped)&gt;; minimum 0 |

### node

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `kind` | yes | `principal`, `executor`, `service`, `resource`, `tool`, `store`, `credential`, `control` |
| `owner` | yes | Fact&lt;Ref&lt;nodes&gt; (principal)&gt; |
| `permission_refs` | no | Set&lt;Ref&lt;capabilities&gt;&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### execution-context

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `actor_id` | yes | Ref&lt;nodes&gt; (principal, executor, service) |
| `task_id` | yes | Ref&lt;tasks&gt; |
| `workflow_id` | yes | Ref&lt;workflows&gt; |
| `initial_visible_objects` | yes | Fact&lt;Set&lt;Ref&lt;object_versions&gt;&gt;; minimum 0&gt; |
| `input_visibility` | yes | Fact&lt;`visible`, `not_visible`&gt; |
| `retain_inputs` | yes | Fact&lt;boolean&gt; |
| `visibility_complete` | yes | Fact&lt;boolean&gt; |
| `isolated_from` | yes | Fact&lt;Set&lt;Ref&lt;execution_contexts&gt;&gt;; minimum 0&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### location

| Field | Required | Type / allowed values |
|---|---|---|
| `node_id` | yes | Ref&lt;nodes&gt; (principal, executor, service, resource, tool, store, control) |
| `context_id` | yes | Ref&lt;execution_contexts&gt; or `not_applicable` |

### production

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `candidate_action`, `historical`, `unknown` |
| `action_id` | no | Ref&lt;actions&gt; |
| `reason` | no | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### authority

| Field | Required | Type / allowed values |
|---|---|---|
| `status` | yes | Fact&lt;`none`, `task`, `policy`&gt; |
| `task_ids` | yes | Fact&lt;Set&lt;Ref&lt;tasks&gt;&gt;; minimum 0&gt; |
| `control_ids` | yes | Fact&lt;Set&lt;Ref&lt;controls&gt;&gt;; minimum 0&gt; |
| `approval_refs` | yes | Fact&lt;Set&lt;Ref&lt;approval_rights&gt;&gt;; minimum 0&gt; |

### object-version

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `logical_id` | yes | string |
| `version` | yes | string |
| `origin_kind` | yes | `root`, `derived`, `unknown` |
| `existence` | yes | `snapshot_initial`, `candidate_produced` |
| `parents` | yes | Fact&lt;Set&lt;Ref&lt;object_versions&gt;&gt;; minimum 0&gt; |
| `parents_complete` | yes | Fact&lt;boolean&gt; |
| `production` | yes | [production](#production) |
| `initial_locations` | yes | Set&lt;[location](#location)&gt;; minimum 0 |
| `restriction_ids` | yes | Fact&lt;Set&lt;Ref&lt;restrictions&gt;&gt;; minimum 0&gt; |
| `restrictions_complete` | yes | Fact&lt;boolean&gt; |
| `instruction_authority` | yes | [authority](#authority) |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### port

| Field | Required | Type / allowed values |
|---|---|---|
| `port_id` | yes | string |
| `object_version_id` | yes | Ref&lt;object_versions&gt; |
| `location_node_id` | yes | Ref&lt;nodes&gt; (principal, executor, service, resource, tool, store, control) |
| `context_id` | yes | Ref&lt;execution_contexts&gt; or `not_applicable` |

### effect

**deliver**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `deliver` |
| `id` | yes | string |
| `input_port_ids` | yes | Set&lt;string&gt;; minimum 1 |
| `output_port_id` | yes | string |

**produce**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `produce` |
| `id` | yes | string |
| `input_port_ids` | yes | Set&lt;string&gt;; minimum 1 |
| `output_port_id` | yes | string |

**activate_authorizations**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `activate_authorizations` |
| `id` | yes | string |
| `capability_ids` | yes | Set&lt;Ref&lt;capabilities&gt;&gt;; minimum 0 |
| `task_grant_ids` | yes | Set&lt;Ref&lt;task_grants&gt;&gt;; minimum 0 |

**select_policy**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `select_policy` |
| `id` | yes | string |
| `control_id` | yes | Ref&lt;controls&gt; |
| `policy_version_id` | yes | string |
| `fields` | yes | Set&lt;`decision_mode`, `deny_clauses`, `coverage`, `checked_parameters`, `binding`, `timing`, `failure_behavior`, `comment`&gt;; minimum 1 |

**revoke**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `revoke` |
| `id` | yes | string |
| `authorization_ref` | yes | [typed_ref](#typed-ref) |

**stop**

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `stop` |
| `id` | yes | string |
| `target` | yes | [typed_ref](#typed-ref) |


### action

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `task_id` | yes | Ref&lt;tasks&gt; |
| `workflow_id` | yes | Ref&lt;workflows&gt; |
| `context_id` | yes | Ref&lt;execution_contexts&gt; |
| `actor_id` | yes | Ref&lt;nodes&gt; (principal, executor, service) |
| `operation_id` | yes | Ref&lt;operations&gt; |
| `interface_id` | yes | Ref&lt;interfaces&gt; |
| `purpose_id` | yes | Ref&lt;purposes&gt; |
| `effect_time` | yes | Fact&lt;timestamp&gt; |
| `inputs` | yes | List&lt;[port](#port)&gt;; minimum 0 |
| `outputs` | yes | List&lt;[port](#port)&gt;; minimum 0 |
| `success_dependencies` | yes | Set&lt;Ref&lt;actions&gt;&gt;; minimum 0 |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |
| `effects` | yes | List&lt;[effect](#effect)&gt;; minimum 0 |
| `group_id` | no | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### grant

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `issuer` | yes | Fact&lt;Ref&lt;nodes&gt; (principal)&gt; |
| `clauses` | yes | List&lt;[scope](#scope)&gt;; minimum 1 |
| `validity` | yes | Fact&lt;[validity](#validity)&gt; |
| `revocation` | yes | Fact&lt;[revocation](#revocation)&gt; |
| `initially_active` | yes | Fact&lt;boolean&gt; |
| `approval_refs` | yes | Fact&lt;Set&lt;Ref&lt;approval_rights&gt;&gt;; minimum 0&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### capability

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `issuer` | yes | Fact&lt;Ref&lt;nodes&gt; (principal, credential)&gt; |
| `clauses` | yes | List&lt;[scope](#scope)&gt;; minimum 1 |
| `validity` | yes | Fact&lt;[validity](#validity)&gt; |
| `revocation` | yes | Fact&lt;[revocation](#revocation)&gt; |
| `initially_active` | yes | Fact&lt;boolean&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### approval

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `holder` | yes | Ref&lt;nodes&gt; (principal) |
| `rights` | yes | Set&lt;`issue_task_grant`, `release_restriction`&gt;; minimum 1 |
| `restriction_ids` | yes | Fact&lt;Set&lt;Ref&lt;restrictions&gt;&gt;; minimum 0&gt; |
| `clauses` | yes | List&lt;[scope](#scope)&gt;; minimum 1 |
| `validity` | yes | Fact&lt;[validity](#validity)&gt; |
| `revocation` | yes | Fact&lt;[revocation](#revocation)&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### release

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `issuer` | yes | Fact&lt;Ref&lt;nodes&gt; (principal)&gt; |
| `restriction_ids` | yes | Fact&lt;Set&lt;Ref&lt;restrictions&gt;&gt;; minimum 0&gt; |
| `clauses` | yes | List&lt;[scope](#scope)&gt;; minimum 1 |
| `validity` | yes | Fact&lt;[validity](#validity)&gt; |
| `revocation` | yes | Fact&lt;[revocation](#revocation)&gt; |
| `approval_refs` | yes | Fact&lt;Set&lt;Ref&lt;approval_rights&gt;&gt;; minimum 0&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### restriction-clause

| Field | Required | Type / allowed values |
|---|---|---|
| `operations` | yes | Fact&lt;Set&lt;Ref&lt;operations&gt;&gt;; minimum 0&gt; |
| `interfaces` | yes | Fact&lt;Set&lt;Ref&lt;interfaces&gt;&gt;; minimum 0&gt; |
| `recipients` | yes | Fact&lt;Set&lt;Ref&lt;nodes&gt; (principal, executor, service, resource, tool, store, control) or `not_applicable`&gt;; minimum 0&gt; |
| `purposes` | yes | Fact&lt;Set&lt;Ref&lt;purposes&gt;&gt;; minimum 0&gt; |
| `workflows` | yes | Fact&lt;Set&lt;Ref&lt;workflows&gt;&gt;; minimum 0&gt; |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |

### restriction

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `source_object_id` | yes | Ref&lt;object_versions&gt; |
| `applies_to_operations` | yes | Fact&lt;Set&lt;Ref&lt;operations&gt;&gt;; minimum 0&gt; |
| `allowed_clauses` | yes | List&lt;[restriction_clause](#restriction-clause)&gt;; minimum 0 |
| `approval_refs` | yes | Fact&lt;Set&lt;Ref&lt;approval_rights&gt;&gt;; minimum 0&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### policy

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `coverage` | yes | Fact&lt;List&lt;[scope](#scope)&gt;; minimum 0&gt; |
| `checked_parameters` | yes | Fact&lt;Set&lt;`task`, `actor`, `object_version`, `operation`, `interface`, `recipient`, `purpose`, `effect_time`, `workflow_conditions`&gt;; minimum 0&gt; |
| `binding` | yes | Fact&lt;`bound`, `unbound`&gt; |
| `timing` | yes | Fact&lt;`before_effect`, `after_effect`&gt; |
| `decision_mode` | yes | Fact&lt;`authorization`, `deny_table`, `external`, `unsupported`&gt; |
| `deny_clauses` | yes | Fact&lt;List&lt;[scope](#scope)&gt;; minimum 0&gt; |
| `failure_behavior` | yes | Fact&lt;`deny`, `pause`, `allow`&gt; |
| `unsupported_reason` | no | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### control

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `node_id` | yes | Ref&lt;nodes&gt; (control) |
| `property_ids` | yes | Set&lt;Ref&lt;properties&gt;&gt;; minimum 1 |
| `initial_policy` | yes | Fact&lt;string&gt; |
| `policy_versions` | yes | List&lt;[policy](#policy)&gt;; minimum 1 |
| `modifiable_fields` | yes | Fact&lt;Set&lt;`decision_mode`, `deny_clauses`, `coverage`, `checked_parameters`, `binding`, `timing`, `failure_behavior`, `comment`&gt;; minimum 0&gt; |
| `responsible_principal` | yes | Fact&lt;Ref&lt;nodes&gt; (principal)&gt; |
| `modification_paths_complete` | yes | Fact&lt;boolean&gt; |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### semantic-influence

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `kind` | yes | `semantic_influence` |
| `source_object_id` | yes | Ref&lt;object_versions&gt; |
| `action_id` | yes | Ref&lt;actions&gt; |
| `slot` | yes | `payload`, `recipient`, `operation`, `task_scope`, `policy` |
| `context_id` | yes | Ref&lt;execution_contexts&gt; |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### delegation

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `kind` | yes | `delegation` |
| `parent_actor_id` | yes | Ref&lt;nodes&gt; (principal, executor, service) |
| `child_actor_id` | yes | Ref&lt;nodes&gt; (principal, executor, service) |
| `action_id` | yes | Ref&lt;actions&gt; |
| `parent_task_id` | yes | Ref&lt;tasks&gt; |
| `child_task_id` | yes | Ref&lt;tasks&gt; |
| `parent_grant_ids` | yes | Set&lt;Ref&lt;task_grants&gt;&gt;; minimum 0 |
| `child_grant_ids` | yes | Set&lt;Ref&lt;task_grants&gt;&gt;; minimum 0 |
| `capability_ids` | yes | Set&lt;Ref&lt;capabilities&gt;&gt;; minimum 0 |
| `extension_approval_refs` | yes | Fact&lt;Set&lt;Ref&lt;approval_rights&gt;&gt;; minimum 0&gt; |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### observation

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `kind` | yes | `observation` |
| `source` | yes | [typed_ref](#typed-ref) |
| `observer_id` | yes | Ref&lt;nodes&gt; (principal, service, control) |
| `event_kinds` | yes | Set&lt;`proposal`, `attempt`, `policy_decision`, `execution`, `effect_observed`&gt;; minimum 1 |
| `channel` | yes | string |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### intervention

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `kind` | yes | `intervention` |
| `actor_id` | yes | Ref&lt;nodes&gt; (principal, control) |
| `target` | yes | [typed_ref](#typed-ref) |
| `operation` | yes | `pause`, `stop`, `revoke` |
| `capability_refs` | yes | Fact&lt;Set&lt;Ref&lt;capabilities&gt;&gt;; minimum 0&gt; |
| `latency` | yes | Fact&lt;[duration](#duration)&gt; |
| `conditions` | yes | List&lt;[condition](#condition)&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### relation

- [semantic_influence](#semantic-influence)
- [delegation](#delegation)
- [observation](#observation)
- [intervention](#intervention)

### response-phases

| Field | Required | Type / allowed values |
|---|---|---|
| `kind` | yes | `sequential_phases` |
| `detection` | yes | Fact&lt;[duration](#duration)&gt; |
| `escalation` | yes | Fact&lt;[duration](#duration)&gt; |
| `decision` | yes | Fact&lt;[duration](#duration)&gt; |
| `stop_effect` | yes | Fact&lt;[duration](#duration)&gt; |
| `sequential` | yes | Fact&lt;boolean&gt; |
| `nonoverlapping` | yes | Fact&lt;boolean&gt; |

### responsibility

| Field | Required | Type / allowed values |
|---|---|---|
| `principal` | yes | Fact&lt;Ref&lt;nodes&gt; (principal)&gt; |
| `observation_refs` | yes | Fact&lt;Set&lt;Ref&lt;relations&gt;&gt;; minimum 0&gt; |
| `intervention_refs` | yes | Fact&lt;Set&lt;Ref&lt;relations&gt;&gt;; minimum 0&gt; |
| `inspectable_basis` | yes | Fact&lt;boolean&gt; |
| `verification_reliable` | yes | Fact&lt;boolean&gt; |
| `reviewer_capable` | yes | Fact&lt;boolean&gt; |
| `response` | yes | Fact&lt;[duration](#duration) OR [response_phases](#response-phases)&gt; |
| `consequence_window` | yes | Fact&lt;[duration](#duration)&gt; |
| `trigger` | yes | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### obligation

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `origin` | yes | `supplied` |
| `property_id` | yes | Ref&lt;properties&gt; |
| `task_id` | yes | Ref&lt;tasks&gt; |
| `applicable` | yes | Fact&lt;boolean&gt; |
| `affected_refs` | yes | List&lt;[typed_ref](#typed-ref)&gt;; minimum 0 |
| `source_refs` | yes | Fact&lt;Set&lt;Ref&lt;object_versions&gt;&gt;; minimum 0&gt; |
| `influence_refs` | yes | Fact&lt;Set&lt;Ref&lt;relations&gt;&gt;; minimum 0&gt; |
| `action_refs` | yes | Fact&lt;Set&lt;Ref&lt;actions&gt;&gt;; minimum 0&gt; |
| `destination_refs` | yes | Fact&lt;Set&lt;Ref&lt;nodes&gt; (principal, executor, service, resource, tool, store, control)&gt;; minimum 0&gt; |
| `persistence_refs` | yes | Fact&lt;Set&lt;Ref&lt;nodes&gt; (store)&gt;; minimum 0&gt; |
| `control_refs` | yes | Fact&lt;Set&lt;Ref&lt;controls&gt;&gt;; minimum 0&gt; |
| `responsibility` | yes | [responsibility](#responsibility) |
| `unknown_items` | yes | List&lt;string&gt;; minimum 0 |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### evidence

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `source` | yes | string |
| `acquisition` | yes | `supplied_assertion`, `configuration_read`, `model_deduction`, `runtime_observation`, `external_report` |
| `claim` | yes | string |
| `scope` | yes | List&lt;[typed_ref](#typed-ref)&gt;; minimum 0 |
| `snapshot_id` | yes | string |
| `recorded_at` | yes | Fact&lt;timestamp&gt; |
| `model_involvement` | yes | Fact&lt;`none`, `generated`, `assisted`&gt; |
| `transformations` | yes | List&lt;string&gt;; minimum 0 |
| `lineage_refs` | yes | Fact&lt;Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0&gt; |
| `applicability` | yes | `current`, `expired`, `configuration_changed`, `conflict`, `unresolved` |
| `limits` | yes | List&lt;string&gt;; minimum 0 |

### event

| Field | Required | Type / allowed values |
|---|---|---|
| `id` | yes | string |
| `run_id` | yes | string |
| `reported_event_kind` | yes | `proposal`, `attempt`, `policy_decision`, `execution`, `effect_observed` |
| `action_id` | yes | Ref&lt;actions&gt; |
| `object_ids` | yes | Set&lt;Ref&lt;object_versions&gt;&gt;; minimum 0 |
| `observer_id` | yes | Ref&lt;nodes&gt; (principal, service, control) |
| `environment` | yes | `declared_model`, `isolated_experiment`, `deployment` |
| `occurred_at` | yes | Fact&lt;timestamp&gt; |
| `recorded_at` | yes | timestamp |
| `details` | yes | string |
| `verified` | no | boolean |
| `claimed_origin` | no | string |
| `evidence_refs` | yes | Set&lt;Ref&lt;evidence&gt;&gt;; minimum 0 |

### limits

| Field | Required | Type / allowed values |
|---|---|---|
| `max_input_bytes` | no | integer; minimum 1 |
| `max_depth` | no | integer; minimum 1 |
| `max_records` | no | integer; minimum 1 |
| `max_actions` | no | integer; minimum 1 |
| `max_states` | no | integer; minimum 1 |
| `max_transition_checks` | no | integer; minimum 1 |
| `max_scope_combinations` | no | integer; minimum 1 |
| `max_clause_checks` | no | integer; minimum 1 |
| `max_findings` | no | integer; minimum 1 |
