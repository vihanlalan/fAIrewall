# Deploying the fAIrewall Lab on Google Cloud

One public link, a private fleet behind it, and every Google product doing a real job.

```
                 public                        private (IAM: only the Lab may call them)
judge ──HTTPS──▶ fw-lab (Cloud Run) ──ID token──▶ fw-gateway-a, fw-gateway-b (Cloud Run)
                   │  Gemini on Vertex AI (agent)          │
                   │  Model Armor (deep check)             │
                   └──────────── Cloud SQL for PostgreSQL ◀┘  sessions · freezes · approvals ·
                                        ▲                     audit chains · learning · ledger
        Cloud Scheduler ─every 10 min─▶ fw-anchor (Cloud Run job) ──▶ Cloud Storage (retention, optional lock)
                                                                └──▶ Base Sepolia (if a key is configured)
```

| Google product | What it does here |
|---|---|
| Vertex AI (Gemini) | The support agent that proposes actions. Called with the Lab's service account, so no API key exists. |
| Model Armor | The deep check on routed content (untrusted input, tainted sessions, high-risk tools). |
| Cloud Run | The Lab (public), two gateways and the control plane (private), the migration and anchor jobs. |
| Cloud SQL for PostgreSQL | Shared state for every instance: sessions, freezes, approvals, audit chains, learning, sandbox ledger. |
| Cloud Build, Artifact Registry | One image, versioned by git commit. |
| Secret Manager, IAM | Database URL, gateway and reviewer keys, optional chain key; one service account per service. |
| Cloud Scheduler, Cloud Run Jobs | Anchoring every 10 minutes, one task at a time, retries are safe (batches are leased). |
| Cloud Storage | Sealed evidence batches, with a retention period; Bucket Lock is an explicit, irreversible option. |
| Cloud Logging, Cloud Monitoring | Structured logs per enforcement event (run, action, gateway, latency); log-based metrics; budget alert. |

## Prerequisites

- A project with billing enabled, and you as Owner (or the roles to create the resources below).
- The Google Cloud CLI, logged in: `gcloud auth login`.
- Run from the repository root.

## Deploy

```bash
PROJECT_ID=your-project ./deploy/gcp/deploy.sh
```

It is idempotent: re-running it updates in place. It prints the public Lab URL at the end.

Options (environment variables): `REGION` (default `asia-south1`), `ARMOR_LOCATION` (default the same;
`asia-south1` has limited Model Armor support and skips non-English injection checks, so use
`us-central1` if that matters), `GEMINI_MODEL` (default `gemini-3.5-flash-lite`), `VERTEX_LOCATION`
(default `global` for standard pay-as-you-go), `SQL_TIER`, `RETENTION`, `LOCK_BUCKET=yes` (asks you to
type the bucket name, then locks retention **permanently**), `ANCHOR_KEY_SECRET` (a Secret Manager secret
holding a Base Sepolia private key; get test ETH from a Base Sepolia faucet), `BILLING_ACCOUNT` + `BUDGET_INR`.

## Check it

```bash
LAB_URL=https://fw-lab-xxxx.a.run.app ./deploy/gcp/smoke.sh
```

The smoke check exits nonzero unless it verifies a deterministic block with Model Armor skipped, a fresh
Model Armor filter result, a learned block, a live Vertex Gemini tool proposal, two distinct remote Cloud Run
gateway acknowledgments, and a valid Merkle proof with a confirmed Cloud Storage receipt. It checks the
gateway service identities returned by the services. Set `SMOKE_REQUIRE_EVM=true` to also require the
optional on-chain confirmation. `SMOKE_ANCHOR_TIMEOUT_S` controls how long it polls for publication.

The deploy script runs `fw-anchor` once before printing the Lab URL. After that, Cloud Scheduler triggers it
every ten minutes. The job reads `lab_audit`, the same PostgreSQL schema the Lab uses. Its bucket objects live
under `fairewall-lab-anchors/`. A scheduled publish failure leaves the affected batch pending in the Lab.
To publish a freshly generated run for a rehearsal without waiting for the schedule, run:

```bash
gcloud run jobs execute fw-anchor --project "$PROJECT_ID" --region "${REGION:-asia-south1}" --wait
```

Open **Console → Evidence** after the job finishes and check that the run's records are anchored. The smoke
check verifies the pre-seeded sample proof. Use this extra step to verify publishing a new judge-run batch.
For **Console → Approvals & learning**, run chapter 4 in Demo, then approve from Console. Return to Demo and
confirm that the held action produced exactly one delivery.

See [the product explanation and diagrams](../../docs/fairewall-lab.md) for the SDK workflow and demo boundaries.

## Live vs recorded

The Lab always works without Google credentials: proposals come from a labelled recorded script and Model
Armor shows as *Unavailable*. It switches to live when the service has:

- `GOOGLE_GENAI_USE_VERTEXAI=true`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` (Gemini on Vertex AI), or
  `GEMINI_API_KEY` (AI Studio key), and
- `MODEL_ARMOR_TEMPLATE=projects/P/locations/L/templates/T`.

The deploy script sets these. Locally: `gcloud auth application-default login`, then export the same
variables and run `python -m fairewall.lab --port 8080`.

## Sizing and limits

- Database connections: each Lab instance uses at most `FAIREWALL_DB_POOL_SIZE` (10) per store pool; with
  `--max-instances 4` plus gateways and jobs this stays well under `db-g1-small`'s limit. Raise
  `SQL_TIER` before raising instance counts.
- Paid calls are capped in the app per sandbox and globally per hour (`LAB_*` limits in
  `fairewall.lab.runtime`); a used-up quota fails per policy and says so.
- Gateways read freezes from Cloud SQL on each check (cached ≤ 1 s), so no background CPU is needed;
  `--min-instances 1` keeps them warm for the kill-switch chapter.
