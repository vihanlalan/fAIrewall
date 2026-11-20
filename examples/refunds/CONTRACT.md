# Refund desk API contract

This is the contract between the refund-desk backend (`examples/refunds/backend.py`) and the frontend. Every response shape below has a real example in [`fixtures/`](fixtures/). Each fixture was produced by running the backend itself (`python examples/refunds/make_fixtures.py`), so the fixtures can't drift from the code.

## Authentication

Send `Authorization: Bearer <key>` on every request except `/api/health`.

| Key | Who holds it | Can do |
|---|---|---|
| Operator key (`REFUND_OPERATOR_KEY`) | The frontend | Start runs, read runs, actions and the ledger, retry a run |
| Reviewer key (`REFUND_REVIEWER_KEY`) | Finance | Approve or reject held actions, reconcile, read everything |

The two keys must differ. The reviewer's name on a decision comes from the server's configuration (`REFUND_REVIEWER_NAME`), never from the request. The agent's identity is also fixed on the server.

## The run object

Returned by `POST /api/runs`, `GET /api/runs/{id}`, `POST /api/runs/{id}/retry`, and inside review and reconcile responses.

| Field | Type | Meaning |
|---|---|---|
| `run_id` | string | One agent conversation. Stays the same across pause and resume. |
| `action_id` | string \| null | The most recent action the model proposed. Matches the approval and the audit trail. |
| `source` | `"live"` \| `"recorded"` | Live Gemini, or a recorded script. Always show this, so no one mistakes a recording for a live run. |
| `model` | string | The model that actually answered, as reported by Gemini (e.g. `gemini-2.5-flash`), or `recorded-script`. |
| `status` | see below | Where the run is now. |
| `reason_codes` | string[] | Rule IDs behind the latest action's outcome, e.g. `financial.transaction_limit`. |
| `policy_version` | string | Policy name and fingerprint in force, e.g. `refund-review-v2 (aff7f6da9333)`. |
| `receipt` | string \| null | Sandbox ledger receipt, only if money moved. |
| `ledger_effect` | object | `{"changed": false}`, or `{"changed": true, "type": "refund", "order_id", "amount_cents", "receipt"}`. |
| `final_text` | string \| null | The answer to show the operator. |
| `model_latency_ms` | number | Total time spent waiting for the model in this run. |
| `policy_latency_ms` | number | Total time fAIrewall added: decisions plus their durable writes, excluding the ledger's own time. |
| `turns` | number | Model turns used (capped at 6). |
| `awaiting_action_id` | string \| null | Set while the run waits for a person or for reconciliation. |
| `actions` | Action[] | Every action in this run, oldest first. |
| `error` | object \| null | `{kind, message}` when the run stopped on an error. |
| `message`, `scenario`, `created_at`, `updated_at` | | The operator's message, the recorded scenario name, and timestamps (Unix seconds). |

### Run status

| `status` | What the UI should do |
|---|---|
| `awaiting_approval` | Show "waiting for finance". The action is in `GET /api/reviews`. |
| `completed` | Show `final_text`. Check `ledger_effect` to see whether money moved. |
| `needs_reconciliation` | The ledger didn't answer, so the outcome is unknown. `final_text` says so. Offer **Reconcile** to a reviewer. Never show it as refunded. |
| `model_error` | The model call failed (`error.kind`: `timeout`, `api_error`, `not_configured`). Offer **Retry**. A retry never repeats an action that already ran. |
| `no_response`, `unsupported_response` | The model returned nothing usable. Offer **Retry**. |
| `turn_limit` | The model used 6 turns without finishing. |

## The action object

Returned in `run.actions`, `GET /api/actions/{id}`, `GET /api/reviews` and review responses.

| Field | Meaning |
|---|---|
| `action_id`, `tool` | `tool` is `lookup_order` or `refund`. |
| `status` | `executed`, `pending_approval`, `blocked`, `rejected`, `expired`, `declined` (the ledger refused at write time, e.g. more than the order has left), `needs_reconciliation` or `cancelled` (reconciled: confirmed not written). |
| `order_id`, `amount_cents` | What was asked. Money is always integer US cents: 4000 is $40.00. |
| `reason_codes`, `explanation` | Rule IDs, and the same in plain English for display. |
| `receipt`, `ledger_effect` | As on the run. |
| `reviewer` | The reviewer's name once decided. |
| `policy_hash` | Fingerprint of the policy that made the last decision. |
| `policy_latency_ms` | fAIrewall time for this action (in `run.actions` only). |
| `timeline` | (`GET /api/actions/{id}` only) Every status change with time, reviewer and policy hash. This comes from the audit trail. |
| `expires_at`, `run_ids` | (`/api/reviews` only) When the request lapses, and the runs waiting on it. |

## Endpoints

| Method and path | Key | Body | Returns |
|---|---|---|---|
| `GET /api/health` | none | | `live_model`, `model`, `recorded_scenarios`, `policy_version`, `definitions_pending_review` |
| `POST /api/runs` | operator | `{"message": "...", "source": "live"\|"recorded", "scenario": optional}` | 201 + run. 503 if `live` is chosen without a Gemini key. |
| `GET /api/runs` | either | | `{"runs": [run, ...]}`, newest first |
| `GET /api/runs/{id}` | either | | run |
| `POST /api/runs/{id}/retry` | operator | | run |
| `GET /api/reviews` | reviewer | | `{"pending": [action, ...]}` |
| `POST /api/reviews/{action_id}` | reviewer | `{"approve": true\|false}` | `{"action", "already_decided", "decision_latency_ms", "runs": [run, ...]}` |
| `POST /api/actions/{id}/reconcile` | reviewer | | `{"action", "runs"}`. Settles from the ledger's own record and never re-sends. |
| `GET /api/actions/{id}` | either | | action with `timeline` |
| `GET /api/ledger` | either | | `orders`, `refunds`, and `consistency: {ledger_refunds, executed_refund_actions, agrees, problems}` |

**Approving twice is safe.** A second approval, or two at once, returns the first decision's outcome with `already_decided: true`. The ledger is written once.

## Demo orders

| Order | Item | Paid | Already refunded | What it shows |
|---|---|---|---|---|
| ORD-1001 | Blender | $120.00 | $0.00 | $40 waits for finance; $140 is blocked by the $100 cap |
| ORD-1002 | Kettle | $45.50 | $0.00 | Lookup only |
| ORD-1003 | Office chair | $300.00 | $280.00 | $50 is approved, then declined by the ledger (only $20 left) |

## Recorded scenarios

For `source: "recorded"`, a scenario is picked from the message when `scenario` isn't given:

- `refund_40` matches "$40";
- `refund_over_cap` matches "$140";
- `refund_beyond_refundable` matches "ORD-1003";
- `lookup_only` matches "ORD-1002" or "status".

Recorded final answers are filled in from the real outcome, so they stay accurate.
