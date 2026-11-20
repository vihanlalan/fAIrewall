# Deploying the fAIrewall Lab on Vercel

One Vercel project runs the Lab (UI, API, SDK, policy engine). Neon Postgres holds every bit of state.
Google provides Gemini (AI Studio key) and Model Armor (keyless, through Workload Identity Federation).

| Piece | Where |
|---|---|
| Lab: Demo and Console, agent runner, policy, approvals, trace | Vercel Python function (`app.py`, FastAPI preset) |
| Sessions, approvals, cases, sandbox ledger, audit chain, Merkle batches | Neon Postgres (`FAIREWALL_DATABASE_URL`) |
| Agent proposals | Gemini API (`GEMINI_API_KEY` from Google AI Studio) |
| Deep screening | Google Model Armor, via a short-lived Vercel OIDC token exchanged for a Google service account |
| Fleet and kill switch | Two in-process gateway identities over the shared database (say "in-process" on stage) |
| Evidence | Sealed and verifiable in the Lab; not published externally (no bucket or chain) |

How it's wired, so you don't have to paste any code:
- **Dependencies.** Vercel installs the `vercel` dependency group in `pyproject.toml`. It ignores `requirements.txt` whenever a `pyproject.toml` exists, so don't add one.
- **Startup.** `app.py` calls `fairewall.vercel.build_app()`. That refuses to start without Postgres, keeps each instance's connection pool small, and turns off prepared statements on Neon's pooled host.
- **Google sign-in.** `fairewall.cloud_auth` writes a keyless Google credential configuration and keeps each request's `x-vercel-oidc-token` where Google's auth library reads it.

Vercel Hobby is for personal, non-commercial use, so confirm the Buildathon demo qualifies.

## 1. Neon

1. Create a Neon project named `fairewall-buildathon`. Pick a region near Vercel's default, `iad1` (AWS us-east-1).
2. Under **Connect**, copy the **pooled** connection string (its host contains `-pooler`). Keep `sslmode=require`.

The Lab creates its tables on first start, so no migration step is needed. To pre-warm instead, run `FAIREWALL_DATABASE_URL='<string>' python -m fairewall.lab --migrate` once from a checkout.

## 2. Vercel project and the recorded Lab

1. Push the repo to GitHub, then go to **Vercel → Add New → Project → import it**. Keep the root directory at the repo root; the preset comes from `vercel.json`.
2. Under **Settings → Environment Variables**, add these for **Production**:

   | Variable | Value |
   |---|---|
   | `FAIREWALL_DATABASE_URL` | the pooled Neon string |

3. Deploy. Open the production URL in a private window and check:
   - Chapter 1 creates one receipt.
   - Chapter 2's over-cap refund is blocked and creates no receipt.
   - For Chapter 4, open **Console → Approvals & learning**, approve the held action, and check there's one delivery in Demo.
   - A second private window gets its own sandbox.

If it fails:
- **Build fails:** check **Deployments → Build Logs**.
- **500 errors:** check **Logs**. The first line names the database or import problem.

## 3. Live Gemini

1. Get a key from **Google AI Studio → API keys**.
2. Add these Production variables:
   - `GEMINI_API_KEY` = your key
   - `GEMINI_MODEL` = a model AI Studio lists, for example `gemini-3.5-flash-lite`
3. Redeploy.

Leave `GOOGLE_GENAI_USE_VERTEXAI` unset. Then:
- `/api/status` should show `"gemini": "gemini-api"`.
- In Demo, choose **Live Gemini** and run Chapter 1. The trace should show a proposal whose source is `live`.

## 4. Model Armor (keyless)

1. In Vercel, go to **Settings → Security → Secure backend access with OIDC federation** and choose the **Team** issuer.
2. Note your team slug (from the team URL) and the project name.
3. In **Google Cloud Shell**, in a project with billing enabled (your AI Pro monthly credit covers this; Model Armor includes 2M free tokens a month), run:

```bash
PROJECT_ID="your-google-project-id"
VERCEL_TEAM="your-vercel-team-slug"
VERCEL_PROJECT="fairewall-lab"

ARMOR_REGION="us-central1"; TEMPLATE_ID="fairewall-lab"
POOL_ID="vercel-lab"; PROVIDER_ID="vercel"; SA_ID="fw-vercel-armor"
SA_EMAIL="${SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
SUBJECT="owner:${VERCEL_TEAM}:project:${VERCEL_PROJECT}:environment:production"

gcloud services enable modelarmor.googleapis.com iam.googleapis.com iamcredentials.googleapis.com \
  sts.googleapis.com --project="$PROJECT_ID"
gcloud iam service-accounts create "$SA_ID" --project="$PROJECT_ID"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" --role="roles/modelarmor.user"
gcloud iam workload-identity-pools create "$POOL_ID" --project="$PROJECT_ID" --location=global \
  --display-name="fAIrewall Vercel"
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" --project="$PROJECT_ID" \
  --location=global --workload-identity-pool="$POOL_ID" --display-name="Vercel production" \
  --issuer-uri="https://oidc.vercel.com/$VERCEL_TEAM" \
  --allowed-audiences="https://vercel.com/$VERCEL_TEAM" \
  --attribute-mapping="google.subject=assertion.sub" \
  --attribute-condition="assertion.sub == '$SUBJECT'"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/subject/$SUBJECT"
gcloud model-armor templates create "$TEMPLATE_ID" --project="$PROJECT_ID" --location="$ARMOR_REGION" \
  --pi-and-jailbreak-filter-settings-enforcement=enabled \
  --pi-and-jailbreak-filter-settings-confidence-level=MEDIUM_AND_ABOVE \
  --malicious-uri-filter-settings-enforcement=enabled

printf 'MODEL_ARMOR_TEMPLATE=projects/%s/locations/%s/templates/%s\n' "$PROJECT_ID" "$ARMOR_REGION" "$TEMPLATE_ID"
printf 'GCP_WIF_AUDIENCE=//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s\n' \
  "$PROJECT_NUMBER" "$POOL_ID" "$PROVIDER_ID"
printf 'GCP_ARMOR_SERVICE_ACCOUNT=%s\n' "$SA_EMAIL"
```

4. Add the three printed lines as **Production** variables in Vercel, then redeploy.
5. In the Lab, go to **Free play → Website**, submit a fresh harmless sentence, and open **What fAIrewall did**. Model Armor should show provenance `live call` with a filter result; `NO_MATCH_FOUND` counts as a completed scan. Then run Chapter 2 to show the deterministic block with Model Armor *skipped*.

`ALREADY_EXISTS` on a re-run is fine. The two audiences above are deliberate:
- `https://vercel.com/TEAM` is what the incoming Vercel token carries.
- `GCP_WIF_AUDIENCE` names the Google provider.

## 5. Troubleshooting

| Symptom | Check |
|---|---|
| `ModuleNotFoundError` in logs | The build installed the `vercel` dependency group (Build Logs: "Installing required dependencies from pyproject.toml"); no `uv.lock` committed that omits it |
| "needs Postgres" | `FAIREWALL_DATABASE_URL` is set for **Production** |
| `prepared statement ... does not exist` | Set `FAIREWALL_DB_POOLER=1` |
| Gemini unavailable or 429 | Key and model ID in AI Studio. Use Recorded mode for the tour meanwhile |
| Model Armor "No Google credentials" / STS 400 | Team issuer mode, team slug, project name, production subject, both audiences |
| Model Armor 403 | The API is enabled and the service account has `roles/modelarmor.user` |
| Model Armor 404 | `MODEL_ARMOR_TEMPLATE` project, location and template ID |
| Proof valid, new records not published | Expected: this setup has no external publisher |

Optional publication: set `FAIREWALL_ANCHOR_BUCKET` (a bucket the service account can write to) and `CRON_SECRET`. Then call `GET /api/cron/anchor` with `Authorization: Bearer $CRON_SECRET`, or add a daily Vercel Cron for that path.

The Google Cloud Run deployment (`deploy/gcp/`) still works if you get credits later.
