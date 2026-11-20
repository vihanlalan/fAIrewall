# fAIrewall and the OWASP Top 10 for Agentic Applications (2026)

This page maps each risk in the **OWASP Top 10 for Agentic Applications for 2026** (OWASP GenAI Security Project, released 9 December 2025) to the fAIrewall controls that address it. Each control is named by its rule ID, as it appears in decisions and the audit log, and each claim has a test you can run.

Source: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

We grade our own coverage plainly:

- **Strong:** fAIrewall enforces the main OWASP mitigations for this risk at the tool-call boundary.
- **Partial:** it enforces some mitigations; others need controls outside fAIrewall.
- **Limited:** one or two supporting controls only; the risk mostly needs other tools.

fAIrewall sits between an agent and its tools. It decides whether each action may run. It does not sandbox code, sign agent-to-agent messages or scan software dependencies, so those parts of the list are marked as gaps rather than claimed.

## Summary

| ID | Risk | Coverage | Main fAIrewall controls |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | Partial | Untrusted-content lock, injection signatures, AI detectors (local and Google Model Armor), per-action gate |
| ASI02 | Tool Misuse and Exploitation | **Strong** | Tool and argument allowlists, money caps, rate limits, egress allowlist |
| ASI03 | Identity and Privilege Abuse | Partial | Role checks per tool, per-action re-check, human approval with separate reviewer key |
| ASI04 | Agentic Supply Chain Vulnerabilities | Limited | Kill switch, policy fingerprint, unknown tools treated as high risk |
| ASI05 | Unexpected Code Execution (RCE) | Partial | Destructive-command signatures in arguments, tool lock after untrusted content, human approval |
| ASI06 | Memory and Context Poisoning | Partial | Tool-output screening, session taint, untrusted-data wrapping |
| ASI07 | Insecure Inter-Agent Communication | Limited | Other agents' output treated as untrusted; audit trail |
| ASI08 | Cascading Failures | **Strong** | Budgets, rate limits, kill switch, replay of past traffic (`fairewall diff`) |
| ASI09 | Human-Agent Trust Exploitation | Partial | Approval queue with re-check, tamper-evident log, secret and PII redaction |
| ASI10 | Rogue Agents | Partial | Kill switch per agent, per run or for all; hash-chained audit; budgets |

## How fAIrewall decides, in one paragraph

Every tool call goes through `inspect` before it runs. Deterministic rules check it first (schema, roles, money, rate, taint, egress, payload). If the call is risky, a local AI detector can tighten the verdict but never loosen it. The strictest finding wins: **allow**, **review** (a person decides) or **block**. Every verdict is written to a SHA-256 hash-chained audit log, together with the fingerprint of the policy that produced it. Text entering the agent (emails, web pages, tool output) is screened too. Text from outside marks the session as tainted, which locks tools that policy fences off from untrusted content.

---

## ASI01 · Agent Goal Hijack · Partial

**The risk:** instructions hidden in content the agent reads (an email, a web page, a document, a calendar invite) redirect the agent towards the attacker's goal.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation it implements |
|---|---|---|
| **Untrusted-content lock.** Anything the agent fetched rather than was told is marked untrusted. From then on, tools with `forbid_when_tainted` (payments, email, exports) are blocked for that session, whether or not the injection was spotted. | `taint.untrusted_context` | "Treat all natural-language inputs as untrusted"; "minimize the impact of goal hijacking by enforcing least privilege" |
| Signature scan of inbound text: instruction override, role reassignment, fake system prompts, delimiter injection, secret-exfiltration requests, guardrail bypass, urgency/authority lures, encoded payloads, invisible Unicode characters | `injection.*` | "Sanitize and validate any connected data source" |
| Same signatures over the *arguments* of outgoing tool calls, which catches an injected instruction being passed on | `payload.*` | Validate agent intent at run time |
| Local AI detector (tier 1) on risky calls and untrusted text. It can only make a verdict stricter. | `detector.learned` | Content validation |
| Adaptive threat memory: a threat signal unlike anything reviewed goes to a person; the decision is learned, and variants of a confirmed threat are blocked next time even if no rule or detector fires | `adaptive.novel_threat`, `adaptive.learned_threat`, `adaptive.model` | "Human-in-the-loop for high-impact or goal-changing actions"; continuous monitoring |
| Google Cloud Model Armor (optional tier-1 detector): Google's prompt injection, jailbreak and malicious-URL filters on the same risky calls. Fails closed on high-risk routes if Google can't be reached. | `detector.model_armor` | "Sanitize and validate any connected data source"; content validation |
| Every high-impact action is checked at the moment it runs, not once at the start of the task | (all rules) | "At run time, validate both user intent and agent intent before executing goal-changing or high-impact actions" |
| Hash-chained audit log of every verdict | — | "Maintain comprehensive logging and continuous monitoring" |

**Gaps**

- Text detection alone is weak against reworded attacks. On our public benchmark, at 1% false alarms the learned detector catches 10% of LLMail-Inject attacks, 2% of InjecAgent and 0% of BIPIA (`tools/eval_agent_detector.py`). That is why the untrusted-content lock, not text detection, carries this risk.
- The lock works only if the integration marks external content as untrusted (`trust="untrusted"`, or `produces_untrusted_output` on the tool).
- Out of scope for fAIrewall: locking system prompts and "intent capsules".

- We have not yet measured Model Armor on the same agent-attack benchmark (it needs a Google Cloud project). Until then, treat it as an extra layer, not as proof of coverage. Running `tools/eval_agent_detector.py` against it is the next step.

**Check it:** `tests/test_output_inspection.py`, `tests/test_model_armor.py`, and `#attacks/invoice` and `#attacks/hijack` in the demo.

## ASI02 · Tool Misuse and Exploitation · Strong

**The risk:** the agent uses a tool it is allowed to use, but in an unsafe way: wrong arguments, too often, too much money, data sent to the wrong place.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Per-tool policy: required and allowed arguments, regex patterns per argument, unknown tools flagged | `schema.missing_arguments`, `schema.unexpected_arguments`, `schema.pattern_mismatch`, `schema.unknown_tool` | "Least agency and least privilege for tools" |
| Money caps per call and per session. Amounts are read at any depth, from minor units (paise, cents) and from lists. An amount that can't be read is blocked. | `financial.transaction_limit`, `financial.session_budget`, `financial.unparseable_amount`, `financial.negative_amount` | "Adaptive tool budgeting: apply usage ceilings (cost, rate…)" |
| Rate limits per tool and per session | `velocity.tool_rate`, `velocity.session_rate` | Same |
| Approved destinations for any URL or email address in arguments | `egress.unapproved_destination` | "Egress controls" |
| Credentials and bulk personal data blocked from leaving in a tool call | `egress.secret_material`, `egress.bulk_pii` | Egress controls |
| A policy gate outside the model: the model proposes, fAIrewall decides | (the engine) | "Policy enforcement middleware ('intent gate'). Treat LLM or planner outputs as untrusted." |
| Inspect never changes state; budgets move only when a call is committed | — | Prevents a blocked call from using up budget |
| `fairewall diff` replays real traffic against a new policy before it ships | — | "Drift detection" |

**Gaps:** no execution sandbox and no just-in-time credentials. fAIrewall decides; your platform still runs the tool and holds the keys.

**Check it:** `tests/test_rules_financial_nested.py`, `tests/test_policy_diff.py`, and `#attacks/refunds` and `#attacks/loop` in the demo.

## ASI03 · Identity and Privilege Abuse · Partial

**The risk:** an agent uses credentials or permissions beyond its task, or one agent's privileges leak to another.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Roles allowed per tool | `schema.role_denied` | "Mandate per-action authorization: re-verify each privileged step with a centralized policy engine" |
| Every call is checked. Nothing is approved for a whole session in advance. | (the engine) | Same |
| Tools marked `require_human_approval` are held for a person. The approval queue re-checks the call when approved, and no one can approve their own request. | `schema.human_approval_required` | "Apply human-in-the-loop for privilege escalation" |
| A separate reviewer key, so the agent's key can't approve or release anything | gateway | Separation of duties |
| Copilot and Salesforce adapters verify signed tokens (issuer, audience, expiry) | adapters | Bind permissions to subject and audience |

**Gaps**

- On the core HTTP gateway, `principal_roles` come from the request body, so a compromised agent can claim roles. This is being fixed: roles will come from the API key or a signed token.
- No short-lived tokens and no tracking of delegated permissions.

**Check it:** `tests/test_approvals.py`, `tests/test_auth_hardening.py`.

## ASI04 · Agentic Supply Chain Vulnerabilities · Limited

**The risk:** a tampered tool, plugin, MCP server, prompt template or dependency compromises the agent.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| **Kill switch** to stop every agent, one agent or one run immediately | `killswitch.frozen` | "Supply chain kill switch: implement emergency revocation mechanisms that can instantly disable" |
| Policy fingerprint (SHA-256) recorded on every decision, so you can prove which rules were in force | audit field `policy_fingerprint` | "Pinning: pin prompts, tools, and configs by content hash" (for the policy only) |
| Tools not in the policy are treated as high risk by default | `unknown_tool_risk` | Allowlisting |

**Gaps:** no SBOMs or AIBOMs, no signing or drift detection for MCP tool definitions, no dependency scanning. Use dedicated supply-chain tools for these.

## ASI05 · Unexpected Code Execution (RCE) · Partial

**The risk:** the agent is steered into generating and running code or shell commands.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Arguments to any tool are scanned for destructive data operations that name their target (`DROP TABLE users`, "delete all records", "wipe the backups"), privilege escalation ("grant admin") and encoded payloads | `payload.destructive_action`, `payload.privilege_escalation`, `payload.encoded_payload` | "Do static scans before execution" (at the level of tool arguments) |
| Code-running tools marked `forbid_when_tainted` lock after untrusted content | `taint.untrusted_context` | "Taint-tracking on generated code" |
| Code-running tools can require a person | `schema.human_approval_required` | "Require human approval for elevated runs" |
| Argument patterns restrict what may be passed (e.g. only allow-listed commands) | `schema.pattern_mismatch` | "Keep an allowlist" |

**Gaps**

- fAIrewall doesn't run code, so it provides no sandbox, container isolation or runtime monitoring.
- The signatures target data operations, not shell syntax. A bare `rm -rf /` or `format c:` in a command argument is **not** caught by them today. For a shell or code tool, use `arg_patterns` to allow-list commands, set `forbid_when_tainted`, and require a person.

## ASI06 · Memory and Context Poisoning · Partial

**The risk:** poisoned content gets into the agent's memory, retrieval store or context and keeps steering it later.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Tool output is screened before the agent reads it. A hidden instruction marks the session as tainted. | `output.*` (injection signatures), `taint.untrusted_context` | "Content validation: scan all new memory writes and model outputs" |
| `sanitize()` wraps untrusted content in a labelled data block, so the model is told it is data, not instructions | — | Provenance |
| Secrets and personal data are redacted from output, so they can't be stored in memory | `output.secret_redacted`, `output.pii_redacted` | "Baseline data protection" |
| Per-source trust (Proof of Sampling): content from a source seen for the first time is always deep-checked; a source caught injecting is quarantined, and every item from it is flagged | `sampling.quarantined_source` | "Trust-weight sources"; provenance |
| fAIrewall's own learning memory is guarded against poisoning: only the reviewer key can label, an agent cannot label its own case, a learned allow needs 2 near-identical approvals and never lifts a block, business rule or taint, and every label is audited and revocable | `adaptive.learned_allow` | "Prevent unvalidated writes to memory"; "maintain provenance and rollback" |

**Gaps:** fAIrewall doesn't manage memory stores. It doesn't segment, expire or trust-weight memory, and taint lasts only for one session.

## ASI07 · Insecure Inter-Agent Communication · Limited

**The risk:** messages between agents are spoofed, replayed, intercepted or tampered with.

**What fAIrewall does**

- Another agent's output can be screened as untrusted (`trust="untrusted"`), so a compromised peer can't unlock risky tools for this agent.
- Every decision is recorded in the hash-chained log.

**Gaps:** no mutual TLS, message signing, anti-replay protection or agent registry. Use your service mesh or agent protocol layer for these.

## ASI08 · Cascading Failures · Strong

**The risk:** one fault or bad decision spreads through automated steps and agents faster than people can react.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Per-session spend budgets and per-tool and per-session rate limits | `financial.session_budget`, `velocity.*` | "Implement blast-radius guardrails such as quotas, progress caps"; "rate limiting and monitoring" |
| **Kill switch** to pause everything, one run or one agent | `killswitch.frozen` | "Throttle or pause on anomalies" |
| A policy engine separate from the agent | (the engine) | "Independent policy enforcement: separate planning and execution via an external policy engine" |
| Human gates for high-risk actions | `schema.human_approval_required` | "Output validation and human gates" |
| `fairewall diff OLD NEW LOG` re-runs recorded traffic against a proposed policy and lists every call that would newly pass or fail. The shadow-mode report does the same for a first rollout. | CLI | "Digital twin replay and policy gating: re-run the last week's recorded agent actions" |
| Hash-chained log of every decision | — | "Logging and non-repudiation" |

**Gaps:** no automatic anomaly baselines. Limits are set by policy, not learned.

**Check it:** `tests/test_policy_diff.py`, `tests/test_kill_switch.py`, and `#attacks/loop` in the demo.

## ASI09 · Human-Agent Trust Exploitation · Partial

**The risk:** the agent, or an attacker through it, persuades a person to approve something harmful.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| Approval queue shows the reviewer the exact tool, arguments and reason it was held | approvals | "Explicit confirmations" |
| Approving re-checks the call first. If the policy now blocks it, for example because the budget ran out or the kill switch is on, it is rejected and doesn't run. | approvals | Prevents a stale or socially engineered approval from going through |
| Tamper-evident audit log (each record hashes the one before) | `/v1/audit/verify` | "Immutable logs" |
| Secrets and personal data are redacted from tool output before the agent can repeat them to a person | `output.secret_redacted`, `output.pii_redacted` | "Behavioral detection: monitor sensitive data being exposed" |

**Gaps:** no end-user risk cues in your app's UI and no plan-divergence detection. The log is tamper-evident, not tamper-proof, until the chain head is published externally.

## ASI10 · Rogue Agents · Partial

**The risk:** an agent drifts from its intended behaviour or is taken over, and keeps acting.

**What fAIrewall does**

| Control | Rule ID | OWASP mitigation |
|---|---|---|
| **Kill switch** per agent identity, per run or for everything. It blocks every tool call in scope, even in shadow mode. Freezing works with either key; releasing needs the reviewer key, so a rogue agent can't unfreeze itself. Freezes can be saved to disk to survive restarts, and an unreadable state file freezes everything. | `killswitch.frozen` | "Containment and response: implement rapid mechanisms like kill-switches" |
| Budgets and rate limits cap what a rogue agent can do before anyone notices | `financial.*`, `velocity.*` | Containment |
| Hash-chained audit with the policy fingerprint on every record | — | "Comprehensive, immutable and signed audit logs" (hash-chained; not yet signed) |

**Gaps:** no agent attestation, watchdog agents or behavioural baselines.

**Check it:** `tests/test_kill_switch.py`, and Overview → Kill switch in the gateway console.

---

## What we would add next, in order

1. **Roles from the key, not the request** (ASI03): bind principals and roles to API keys or signed tokens on the core gateway.
2. **Anchor the audit chain head externally** (ASI09, ASI10): publish the head on a schedule, so the log becomes tamper-proof as well as tamper-evident.
3. **MCP tool-definition pinning** (ASI04): hash each tool's description and schema, and flag any change.
4. **Agent-aware detector** (ASI01): retrain the AI tier on agent-style attacks so text detection adds real coverage on top of the untrusted-content lock.

## Running the evidence

```bash
pip install -e ".[proxy]"
pytest -q tests/test_kill_switch.py tests/test_pii_redaction.py tests/test_output_inspection.py \
          tests/test_rules_financial_nested.py tests/test_approvals.py tests/test_policy_diff.py
fairewall demo          # http://localhost:8080/demo shows each attack with and without fAIrewall
```
