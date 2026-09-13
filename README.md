<div align="center">

# AgentGate

**A compiler-backed semantic execution gate for AI tool calls.**

AgentGate constrains generated arguments to valid schemas and request-scoped resources. Before an
action can run, it independently checks current authority, workflow, exact approval, deadlines,
and retry state.

It is a reusable layer between an agent and its tool adapters. The included GitHub workflow
demonstrates the boundary offline, without credentials or network access.

[Problem](#the-problem) | [Guarantee](#the-core-guarantee) | [Design](#how-agentgate-works) |
[Quick start](#quick-start) | [Use cases](#use-cases)

</div>

Valid JSON proves structure, not permission. AgentGate keeps generation-time validity and
execution-time authority separate, so a stale, unapproved, or repeated action fails closed.

The same design can guard ticketing, deployment, document, browser, account, and database tools.

## What this repository is for

AgentGate provides a working reference for developers and researchers building agents that can
read data or cause external effects. It demonstrates how to:

- compile tool contracts into token-level constraints;
- ground generated arguments in request-scoped data;
- keep generation constraints separate from current authorization;
- bind approval and retries to the exact normalized action;
- isolate users and tenants while bounding memory and outputs;
- test failure paths without credentials or network access.

The Rust crate owns the trusted execution rules. The Python package exposes the same boundary for
agent applications. Adapters connect that boundary to a specific service.

## The problem

Valid JSON is not the same as a valid action.

An agent can produce a tool call that matches a schema but still:

- name a resource that was never available to this request;
- use permission that expired while the model was generating;
- act on a different resource than the one previously inspected;
- reuse approval after the action changed;
- repeat a write after a timeout;
- mix data between users or tenants.

AgentGate handles these as separate checks instead of asking the model to enforce them.

## The core guarantee

A tool call only runs if it is structurally valid, references something the current request
actually had access to, and clears a fresh permission and approval check taken immediately
before execution. Any single failure blocks the write; nothing downstream ever sees it.

For a grounded write action `a`:

```text
WriteAllowed(a) = ValidToolCall(a)
                  AND ResourceInSnapshot(a)
                  AND SnapshotIsFresh(a)
                  AND WorkflowAllows(a)
                  AND CurrentPermission(a)
                  AND PolicyAllows(a)
                  AND ExactApproval(a)
                  AND DeadlineIsValid(a)
                  AND RetryIsSafe(a)
```

The write is unreachable when any check fails.

Two boundaries make this work:

1. During generation, the model can produce only a valid tool call using resources from the
   immutable snapshot created for that request.
2. Before execution, AgentGate checks the real permission again and applies the write in the same
   adapter transaction.

The snapshot limits what the model can reference. It does not grant permission to execute.

## How AgentGate works

1. A tool is registered with a versioned schema, semantic requirements, limits, and policy.
2. AgentGate compiles the contract with exactly one compatible constraint engine.
3. A private generation session checks every token selected for that action.
4. The completed action is parsed and independently validated.
5. Workflow, current authorization, exact approval, deadline, and idempotency are checked.
6. The trusted adapter authorizes and applies the write in one transaction.
7. The bounded result and decision evidence are added to the audit log.

There is no runtime engine fallback, schema relaxation, or mask combination.

### Constraint engines

| Requirement | Engine |
| --- | --- |
| Resource membership from request data | [OC-Sidememory](https://github.com/dhanavanthesh/oc-sidememory) |
| Equality or exclusion between fields | [OC-Sidememory](https://github.com/dhanavanthesh/oc-sidememory) |
| Checked uniqueness and counted matches | [OC-Sidememory](https://github.com/dhanavanthesh/oc-sidememory) |
| Supported non-semantic JSON Schema | [MaskForge](https://github.com/dhanavanthesh/maskforge) |
| Measured recursive local-`$ref` JSON Schema profile | [OC-Earley](https://github.com/dhanavanthesh/oc-earley) |

Selection happens when the tool is registered. If the required engine cannot compile the contract,
registration fails.

The OC-Earley route is experimental. Its bounded byte-vocabulary results do not replace validation
with real tokenizer vocabularies.

## Offline example

The repository includes a familiar issue workflow to test the complete boundary without using a
network or credentials:

1. `github.list_issues@1` returns opaque issue handles and creates an immutable snapshot.
2. `github.inspect_issue@1` records which issue and repository revision were inspected.
3. `github.comment_issue@1` requires the same issue, current permission, and approval for the exact
   comment.

The write adapter stores comments only in bounded process memory. It never contacts GitHub.

GitHub is used here because the list, inspect, and write sequence is easy to understand. Other
adapters can apply the same boundary to tickets, deployments, documents, accounts, or databases.

## Quick start

### Requirements

- Rust 1.85 or newer
- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)
- AgentGate, MaskForge, OC-Sidememory, and OC-Earley checked out in the same parent directory

```bash
git clone https://github.com/dhanavanthesh/AgentGate.git agentgate
git clone https://github.com/dhanavanthesh/maskforge.git maskforge
git clone https://github.com/dhanavanthesh/oc-sidememory.git oc-sidememory
git clone https://github.com/dhanavanthesh/oc-earley.git oc-earley

cd agentgate
uv venv
uv pip install maturin pytest
uv run maturin develop --release
```

Run the offline example:

```python
import agentgate


runtime = agentgate.Runtime()
snapshot = runtime.list_issues()
issue = snapshot.writable_issue_handles[0]

runtime.inspect_issue(snapshot, issue)
approval = runtime.approve_comment(snapshot, issue, "Thanks for the update!")
receipt = runtime.comment_issue(
    snapshot,
    issue,
    "Thanks for the update!",
    approval,
)

print(receipt)
```

The complete example is also available as a script:

```bash
uv run python examples/github_simulator.py
```

## Adding a tool

An integration supplies five things:

1. A versioned input schema.
2. Explicit semantic requirements, if the action depends on request data or other fields.
3. A trusted adapter that resolves opaque handles and performs current authorization.
4. A policy that controls tool exposure and workflow transitions.
5. An approval provider for writes that require confirmation.

Generated JSON cannot provide principals, credentials, approval tokens, deadlines, or idempotency
keys. Those values come from trusted application code.

## Use cases

| System | Example rule |
| --- | --- |
| Support agent | Update only a ticket assigned to the current user and inspected in this session |
| Deployment agent | Deploy only an approved revision to an allowed environment |
| Document agent | Edit only documents present in the request's access snapshot |
| Finance agent | Bind approval to the exact account, amount, and operation |
| Retrieval agent | Cite only sources returned for the current request |
| Database agent | Execute only registered operations with bounded arguments and results |
| Retryable tool runner | Reconcile a timeout without repeating a committed write |

These are integration patterns. This repository does not include production adapters for them.

## What AgentGate establishes

Within a registered contract and configured limits, AgentGate establishes that:

- an accepted action matches its tool schema;
- a grounded resource reference came from the request snapshot;
- a write passed current authorization and policy;
- approval matched the exact normalized action and request context;
- an exact retry did not repeat a committed side effect;
- tenant and workflow state remained scoped;
- failures were denied with stable error codes and audit evidence.

AgentGate does not establish that the model understood the user, chose the best action, or completed
the task successfully. It does not make an unsafe tool safe. Those remain application concerns.

## Security and performance design

- Rust owns parsing, validation, routing, authorization, approval, idempotency, and execution
  invariants.
- Python calls the Rust implementation and does not duplicate the security checks.
- Compiled artifacts and vocabularies are immutable and shared.
- Mutable generation state remains private to one sequence.
- A reusable packed token mask avoids a new token list allocation at every step.
- The artifact cache is bounded, observable, and single-flight.
- Workflow, approval, idempotency, output, and audit memory have explicit limits.
- Schema, engine, options, resources, or vocabulary changes create a new artifact identity.
- SHA-256 digests identify evidence. They are not authorization signatures.

## Included

- Rust execution gate and Python bindings
- compiler-backed routing to one constraint engine per action
- bounded snapshots, caches, workflows, approvals, results, retries, and audit records
- offline issue workflow for deterministic examples and tests
- opt-in typed query experiment for bounded read-only evaluation

## Not included

- live service connections or credentials
- persistent approval, workflow, idempotency, or audit stores
- universal JSON Schema or arbitrary grammar support
- free-form SQL or a general database interface
- a guarantee that the model understood the user or selected the best action

The `safe-query-eval` feature is disabled by default and remains separate from the runtime tool
registry. It tests typed query construction and bounded result handling against an offline adapter.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
uv run pytest -q
```

Deterministic tests require no model, credentials, or network. The optional model example requires
a compatible model and tokenizer already available on the machine.

## License

Licensed under the [Apache License 2.0](LICENSE).
