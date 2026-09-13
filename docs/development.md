# Development roadmap

AgentGate is open to research, security, systems, and integration work.

- [ ] Benchmark constraint engines with Qwen and another tokenizer vocabulary.
- [ ] Keep OC-Earley experimental until tokenizer benchmarks pass.
- [ ] Detect true recursive `$ref` cycles during schema routing.
- [ ] Expand differential tests for schemas, token boundaries, and Unicode.
- [ ] Add persistent stores for approvals, workflows, retries, and audit records.
- [ ] Define optional adapters for GitHub, databases, and browsers.
- [ ] Add rate limits, quotas, backpressure, and bounded work queues.
- [ ] Add structured metrics, tracing, and performance profiles.
- [ ] Extend concurrency, crash-recovery, and long-running stress tests.
- [ ] Automate formatting, Clippy, Rust tests, and Python tests in CI.
- [ ] Pin dependencies and automate license and security checks.
- [ ] Document supported schema profiles and the threat model.

External writes must remain disabled in examples unless explicitly configured and approved.
