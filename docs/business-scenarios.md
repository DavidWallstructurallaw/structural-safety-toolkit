# Business starter models

These three templates turn common agent workflows into editable, finite models. Each has an `exposed` and a `controlled` variant with one narrow intervention. All six are complete `sst.model/0.1` inputs for `validate` and `analyze`. They contain synthetic identifiers, declared premises, and virtual times. Exporting or analyzing a template contacts no business service and executes no agent action.

| Template | Business question | Controlled comparison |
|---|---|---|
| `memory-handoff` | Can a confidential CRM summary pass through handoff memory into a customer-facing message? | Add a source-aware authorization gate to the final publication route. |
| `policy-self-modification` | Can the reporting agent weaken its own publication policy, then publish a confidential forecast? | Remove its exact technical capability to select the permissive policy. |
| `human-oversight` | Can an authorized reviewer stop a sensitive publication before its five-second consequence window closes? | Reduce the modeled end-to-end response from 30 seconds to 3 seconds and move the corresponding stop before publication. |

The controlled label describes this modeled intervention. It supplies no production enforcement evidence. A control can block a route in the model while its real effectiveness remains untested.

## Export and analyze

```sh
structural-safety template memory-handoff --variant exposed --output memory-exposed.json
structural-safety template memory-handoff --variant controlled --output memory-controlled.json
structural-safety analyze memory-exposed.json
structural-safety analyze memory-controlled.json

structural-safety template policy-self-modification --variant exposed --output policy-exposed.json
structural-safety template policy-self-modification --variant controlled --output policy-controlled.json
structural-safety analyze policy-exposed.json
structural-safety analyze policy-controlled.json

structural-safety template human-oversight --variant exposed --output review-exposed.json
structural-safety template human-oversight --variant controlled --output review-controlled.json
structural-safety analyze review-exposed.json
structural-safety analyze review-controlled.json
```

With default budgets, all six analyses complete supported checks and return exit 1 for their findings. The controlled models still retain SS005 assurance gaps for declaration-only control evidence. Validate accepts all six with exit 0; validation does not establish that their premises hold. Changing a required fact to unknown can produce an unresolved conclusion and analysis exit 3.

These resources are separate from `demo`. The fixed 18-case experiment protocol and its 15 local executable cases remain unchanged; a business template cannot be passed to `demo` to execute its actions.

## Memory handoff

A support agent reads `crm-case:v1`, derives `case-summary:v1`, writes that exact summary to `store:case-handoff`, then explicitly reads it into the customer-communications context. The summary retains `restriction:crm-confidentiality`. Writing to memory or moving into another context does not release its source restrictions.

The exposed model has an SS001 witness through `read-crm-case`, `summarize-case`, `store-handoff`, `load-handoff`, and `publish-case-summary`. The final publication has task permission but lacks the required source release. Technical ability still allows it to occur in the exposed model.

The controlled file adds only `gate:customer-portal`, a declared strict gate on `if:customer-publish` that checks the complete action and inherited source restrictions before its effect. The same unauthorized publication becomes `blocked_in_model`. Internal summary preparation and handoff storage remain allowed, as does publishing the separate `public-status:v1` notice. This comparison does not solve the issue by disabling normal work.

Before applying this model, replace:

- The CRM object version, derived-summary parents, restrictions, and evidence for source completeness.
- `if:crm-read`, `if:handoff-memory`, and `if:customer-publish` with the actual read, memory, and publication interfaces; identify every relevant destination and alternate route.
- The agent identity, both execution contexts, exact memory location and version, and who may read the handoff.
- Task grants, source-owner approval rights, release exceptions, purposes, validity windows, and revocation facts.
- Gate coverage, checked parameters, check-to-effect binding, failure behavior, and evidence that the agent cannot modify the gate.

The derivation is a declared finite object relationship. The analyzer does not generate a natural-language summary, inspect a real vector database, or establish the absence of arbitrary semantic leakage.

## Policy self-modification

A report-publishing agent reads a confidential forecast for finance review and separately publishes approved public results. A strict gate blocks a confidential upload. The exposed model also gives the agent `cap:select-permissive-publishing-policy`, which lets it select an explicitly declared weaker gate policy despite lacking task authorization for that change. A later confidential upload then creates an SS001 modeled violation.

The controlled file removes only that exact capability. The policy-change candidate remains in the action list and becomes technically infeasible; the later unauthorized upload remains blocked by strict policy. Finance review and approved public-results publication remain available. Removing a task grant alone would not establish the same technical isolation.

Before applying this model, replace:

- The report versions, internal archive, public portal, principal, agent, and actual publication operations.
- The real policy-management interface, control identity, available policy versions, and modifiable fields.
- Every complete `policy_targets` tuple in technical capabilities and task or approval authority. Scope must name the exact control, version, and fields.
- The policy decision behavior, authorization coverage, timing, binding, failure handling, and alternate management routes.
- The evidence and completeness claims used to conclude that no other modification capability is available.

The comparison selects between two finite declared policies. It does not inspect arbitrary policy code, discover hidden administrative credentials, or install a runtime enforcement service.

## Human oversight

An approval officer receives a confidential-report publication proposal at the explicitly described virtual trigger, `2000-01-01T00:00:20Z`. The publication candidate is at `00:00:25Z`, giving a five-second consequence window. Both variants retain the same concrete reviewer, observation relation, technical stop capability, task grant, and exact typed stop target `actions/publish-confidential-report`.

The exposed model declares a 30-second end-to-end response and a stop at `00:00:50Z`. SS006 reports a `responsibility_review_gap`: the reviewer has authority, but the response is too late. The controlled model changes only the response to 3 seconds and the corresponding stop to `00:00:23Z`. Its scoped obligation becomes `satisfied_in_model`, including timely, target-bound intervention authority.

Both models keep the same automated authorization gate. This isolates the human-response question: the late-review finding does not claim that the strict gate leaked a report, and the timely-review result does not prove actual human performance. Proposal time is a documented model premise in the trigger and scope description, rather than a newly observed runtime event.

Before applying this model, replace:

- The exact principal, proposal or pre-effect observation channel, relevant action, recipient, and matching intervention target.
- The responsible person's inspectable basis, verification reliability, and demonstrated capability, preserving unknowns where evidence is missing.
- Stop capability, task authorization, issuer approval, validity and revocation facts, and the concrete stop action's effective time.
- Response and consequence bounds measured from the same trigger. Use an end-to-end response or explicitly sequential, nonoverlapping phases, without double-counting latency.
- Evidence for proposal delivery, stop-effect timing, and all control declarations.

Timeliness requires the response upper bound to be strictly below the consequence-window lower bound. Overlap remains unresolved. A named reviewer or an observation channel cannot supply missing stop authority, competence, or time.

## Adapt the premises before drawing conclusions

Each template's `known` and completeness values describe its finite illustrative setup. For a deployment assessment, replace them with facts supported by configuration, observation, or other scoped evidence; use `unknown` for missing information. Do not preserve a known-complete inventory simply because the template supplied one. Imported events and claimed verification remain attributed external reports unless the toolkit's separate fixed experiment actually observed its own local run.

The report keeps feasibility, authorization, modeled blocking, control assurance, and check completion separate. Review its findings, witnesses, unresolved items, and evidence limits together. There is no total safety score or production-safety certificate.
