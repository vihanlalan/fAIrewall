#!/usr/bin/env bash
# Deploy the fAIrewall Lab to Google Cloud: one command, idempotent (safe to re-run).
#
#   PROJECT_ID=my-project ./deploy/gcp/deploy.sh
#
# Settings (environment variables, all optional except PROJECT_ID):
#   REGION=asia-south1              Cloud Run, Cloud SQL, Artifact Registry, Gemini (Vertex AI)
#   ARMOR_LOCATION=asia-south1      Model Armor template location (us-central1 for full non-English support)
#   GEMINI_MODEL=gemini-2.5-flash   Vertex AI model
#   SQL_TIER=db-g1-small            Cloud SQL machine tier
#   BUCKET=<project>-fairewall-evidence   evidence bucket
#   RETENTION=30d                   bucket retention period
#   LOCK_BUCKET=no                  "yes" locks retention PERMANENTLY (irreversible; asks to confirm)
#   ANCHOR_KEY_SECRET=              Secret Manager secret holding a Base Sepolia key (enables chain anchoring)
#   BILLING_ACCOUNT=                if set, creates a budget alert at BUDGET_INR (default 2000)
#   TAG=<git short sha>             image version
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
REGION="${REGION:-asia-south1}"
ARMOR_LOCATION="${ARMOR_LOCATION:-$REGION}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"
SQL_TIER="${SQL_TIER:-db-g1-small}"
SQL_INSTANCE="${SQL_INSTANCE:-fairewall-sql}"
REPO="${REPO:-fairewall}"
BUCKET="${BUCKET:-${PROJECT_ID}-fairewall-evidence}"
RETENTION="${RETENTION:-30d}"
TAG="${TAG:-$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M)}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/fairewall:${TAG}"
ARMOR_TEMPLATE_ID="${ARMOR_TEMPLATE_ID:-fairewall-pi}"
say() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }

# ------------------------------------------------------------------ preflight
say "Preflight"
command -v gcloud >/dev/null || { echo "Install the Google Cloud CLI first: https://cloud.google.com/sdk"; exit 1; }
gcloud config set project "$PROJECT_ID" >/dev/null
ACCOUNT=$(gcloud config get-value account 2>/dev/null)
[ -n "$ACCOUNT" ] || { echo "Run: gcloud auth login"; exit 1; }
gcloud projects describe "$PROJECT_ID" --format='value(projectId)' >/dev/null
BILLING=$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)' 2>/dev/null || echo "")
[ "$BILLING" = "True" ] || echo "WARNING: billing does not look enabled on $PROJECT_ID; enabling APIs will fail without it."
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
echo "project=$PROJECT_ID region=$REGION image=$IMAGE as $ACCOUNT"

say "Enable APIs"
gcloud services enable run.googleapis.com sqladmin.googleapis.com artifactregistry.googleapis.com \
  cloudbuild.googleapis.com secretmanager.googleapis.com aiplatform.googleapis.com \
  modelarmor.googleapis.com cloudscheduler.googleapis.com storage.googleapis.com \
  logging.googleapis.com monitoring.googleapis.com iam.googleapis.com

# ---------------------------------------------------------------- registry
say "Artifact Registry"
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$REPO" --repository-format docker --location "$REGION"

# --------------------------------------------------------- service identities
say "Service accounts (one per service, least privilege)"
for sa in fw-lab fw-gateway fw-control fw-anchor fw-scheduler; do
  gcloud iam service-accounts describe "$sa@$PROJECT_ID.iam.gserviceaccount.com" >/dev/null 2>&1 || \
    gcloud iam service-accounts create "$sa" --display-name "fAIrewall $sa"
done
SA() { echo "$1@$PROJECT_ID.iam.gserviceaccount.com"; }
grant() { gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$(SA "$1")" \
            --role "$2" --condition None >/dev/null; }
for sa in fw-lab fw-gateway fw-control fw-anchor; do grant "$sa" roles/cloudsql.client; done
grant fw-lab roles/aiplatform.user        # Gemini on Vertex AI
grant fw-lab roles/modelarmor.user        # sanitize calls
grant fw-gateway roles/modelarmor.user
grant fw-lab roles/logging.logWriter
grant fw-anchor roles/logging.logWriter

# ------------------------------------------------------------------ Cloud SQL
say "Cloud SQL for PostgreSQL ($SQL_TIER)"
if ! gcloud sql instances describe "$SQL_INSTANCE" >/dev/null 2>&1; then
  gcloud sql instances create "$SQL_INSTANCE" --database-version POSTGRES_16 --tier "$SQL_TIER" \
    --region "$REGION" --storage-auto-increase --backup-start-time 20:00
fi
gcloud sql databases describe fairewall --instance "$SQL_INSTANCE" >/dev/null 2>&1 || \
  gcloud sql databases create fairewall --instance "$SQL_INSTANCE"
if ! gcloud secrets describe fw-db-url >/dev/null 2>&1; then
  DB_PASS=$(openssl rand -hex 24)
  gcloud sql users create fairewall --instance "$SQL_INSTANCE" --password "$DB_PASS" 2>/dev/null || \
    gcloud sql users set-password fairewall --instance "$SQL_INSTANCE" --password "$DB_PASS"
  CONN=$(gcloud sql instances describe "$SQL_INSTANCE" --format='value(connectionName)')
  printf 'postgresql://fairewall:%s@/fairewall?host=/cloudsql/%s' "$DB_PASS" "$CONN" | \
    gcloud secrets create fw-db-url --data-file=-
fi
CONN=$(gcloud sql instances describe "$SQL_INSTANCE" --format='value(connectionName)')

# ---------------------------------------------------------------- secrets
say "Secrets"
mk_secret() { gcloud secrets describe "$1" >/dev/null 2>&1 || openssl rand -hex 24 | gcloud secrets create "$1" --data-file=-; }
mk_secret fw-gateway-key
mk_secret fw-reviewer-key
for s in fw-db-url fw-gateway-key fw-reviewer-key; do
  for sa in fw-lab fw-gateway fw-control fw-anchor; do
    gcloud secrets add-iam-policy-binding "$s" --member "serviceAccount:$(SA $sa)" \
      --role roles/secretmanager.secretAccessor >/dev/null
  done
done
ANCHOR_ENV=""
if [ -n "${ANCHOR_KEY_SECRET:-}" ]; then
  gcloud secrets add-iam-policy-binding "$ANCHOR_KEY_SECRET" --member "serviceAccount:$(SA fw-anchor)" \
    --role roles/secretmanager.secretAccessor >/dev/null
  ANCHOR_ENV="--set-secrets=FAIREWALL_ANCHOR_KEY=${ANCHOR_KEY_SECRET}:latest"
fi

# ------------------------------------------------------------ evidence bucket
say "Evidence bucket gs://$BUCKET (retention $RETENTION)"
gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1 || \
  gcloud storage buckets create "gs://$BUCKET" --location "$REGION" --uniform-bucket-level-access \
    --retention-period "$RETENTION"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member "serviceAccount:$(SA fw-anchor)" \
  --role roles/storage.objectCreator >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member "serviceAccount:$(SA fw-lab)" \
  --role roles/storage.objectViewer >/dev/null
if [ "${LOCK_BUCKET:-no}" = "yes" ]; then
  echo "Locking the retention policy is PERMANENT: objects cannot be deleted for $RETENTION and the"
  echo "policy can never be shortened or removed. Type the bucket name to confirm:"
  read -r answer
  [ "$answer" = "$BUCKET" ] && gcloud storage buckets update "gs://$BUCKET" --lock-retention-period || echo "Not locked."
fi

# ---------------------------------------------------------- Model Armor template
say "Model Armor template $ARMOR_TEMPLATE_ID in $ARMOR_LOCATION"
TOKEN=$(gcloud auth print-access-token)
ARMOR_URL="https://modelarmor.${ARMOR_LOCATION}.rep.googleapis.com/v1/projects/${PROJECT_ID}/locations/${ARMOR_LOCATION}/templates"
if ! curl -fsS -H "Authorization: Bearer $TOKEN" "$ARMOR_URL/$ARMOR_TEMPLATE_ID" >/dev/null 2>&1; then
  curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$ARMOR_URL?templateId=$ARMOR_TEMPLATE_ID" -d '{"filterConfig":{
      "piAndJailbreakFilterSettings":{"filterEnforcement":"ENABLED","confidenceLevel":"MEDIUM_AND_ABOVE"},
      "maliciousUriFilterSettings":{"filterEnforcement":"ENABLED"}},
      "templateMetadata":{"multiLanguageDetection":{"enableMultiLanguageDetection":true}}}' >/dev/null \
    && echo "created" || echo "WARNING: could not create the Model Armor template (region support? permissions?)"
fi
ARMOR_TEMPLATE="projects/${PROJECT_ID}/locations/${ARMOR_LOCATION}/templates/${ARMOR_TEMPLATE_ID}"

# ---------------------------------------------------------------------- build
say "Build $IMAGE with Cloud Build"
gcloud builds submit --config deploy/gcp/cloudbuild.yaml \
  --substitutions "_REGION=$REGION,_REPO=$REPO,_TAG=$TAG" .

COMMON=(--image "$IMAGE" --region "$REGION" --add-cloudsql-instances "$CONN"
        --set-secrets "FAIREWALL_DATABASE_URL=fw-db-url:latest,FAIREWALL_API_KEY=fw-gateway-key:latest,FAIREWALL_REVIEWER_KEY=fw-reviewer-key:latest"
        --set-env-vars "FAIREWALL_DB_POOL_SIZE=10,GOOGLE_CLOUD_PROJECT=$PROJECT_ID")

# ------------------------------------------------------------------- migrate
say "Migrations (one job, before any service starts)"
gcloud run jobs deploy fw-migrate "${COMMON[@]}" --service-account "$(SA fw-lab)" \
  --update-env-vars FAIREWALL_ROLE=migrate --max-retries 1 --task-timeout 600
gcloud run jobs execute fw-migrate --region "$REGION" --wait

# ------------------------------------------------------------------ services
say "Private gateways (two identities for the fleet chapters)"
for gw in gateway-a gateway-b; do
  gcloud run deploy "fw-$gw" "${COMMON[@]}" --service-account "$(SA fw-gateway)" \
    --update-env-vars "FAIREWALL_ROLE=gateway,FAIREWALL_AUDIT_LOG_ID=$gw" \
    --no-allow-unauthenticated --min-instances 1 --max-instances 3 --concurrency 40 --cpu 1 --memory 512Mi
done
say "Private control plane"
gcloud run deploy fw-control "${COMMON[@]}" --service-account "$(SA fw-control)" \
  --update-env-vars FAIREWALL_ROLE=control --no-allow-unauthenticated --max-instances 2

GW_A=$(gcloud run services describe fw-gateway-a --region "$REGION" --format 'value(status.url)')
GW_B=$(gcloud run services describe fw-gateway-b --region "$REGION" --format 'value(status.url)')
for gw in fw-gateway-a fw-gateway-b; do
  gcloud run services add-iam-policy-binding "$gw" --region "$REGION" \
    --member "serviceAccount:$(SA fw-lab)" --role roles/run.invoker >/dev/null
done

say "Public Lab"
gcloud run deploy fw-lab "${COMMON[@]}" --service-account "$(SA fw-lab)" \
  --update-env-vars "FAIREWALL_ROLE=lab,GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_LOCATION=$REGION,GEMINI_MODEL=$GEMINI_MODEL,MODEL_ARMOR_TEMPLATE=$ARMOR_TEMPLATE,LAB_GATEWAY_A_URL=$GW_A,LAB_GATEWAY_B_URL=$GW_B,FAIREWALL_ANCHOR_BUCKET=$BUCKET,LAB_ENVIRONMENT=cloud:$REGION" \
  --allow-unauthenticated --min-instances 0 --max-instances 4 --concurrency 8 --cpu 1 --memory 1Gi --timeout 120

# ---------------------------------------------------------------- anchoring
say "Anchor job every 10 minutes (Cloud Run job + Cloud Scheduler)"
gcloud run jobs deploy fw-anchor "${COMMON[@]}" --service-account "$(SA fw-anchor)" \
  --update-env-vars "FAIREWALL_ROLE=anchor,FAIREWALL_ANCHOR_BUCKET=$BUCKET" ${ANCHOR_ENV} \
  --parallelism 1 --tasks 1 --max-retries 2 --task-timeout 300
gcloud run jobs add-iam-policy-binding fw-anchor --region "$REGION" \
  --member "serviceAccount:$(SA fw-scheduler)" --role roles/run.invoker >/dev/null
JOB_URI="https://run.googleapis.com/v2/projects/$PROJECT_ID/locations/$REGION/jobs/fw-anchor:run"
gcloud scheduler jobs describe fw-anchor-every-10m --location "$REGION" >/dev/null 2>&1 || \
  gcloud scheduler jobs create http fw-anchor-every-10m --location "$REGION" --schedule "*/10 * * * *" \
    --uri "$JOB_URI" --http-method POST --oauth-service-account-email "$(SA fw-scheduler)"

# ---------------------------------------------------------------- monitoring
say "Log-based metrics"
metric() { gcloud logging metrics describe "$1" >/dev/null 2>&1 || gcloud logging metrics create "$1" \
  --description "$2" --log-filter "$3" >/dev/null; }
metric fw_lab_blocks "fAIrewall Lab blocks" 'jsonPayload.component="fairewall-lab" AND jsonPayload.outcome="block"'
metric fw_lab_model_errors "Gemini errors and fallbacks" 'jsonPayload.component="fairewall-lab" AND jsonPayload.outcome="model_error"'
metric fw_anchor_runs "Anchor job runs" 'resource.type="cloud_run_job" AND resource.labels.job_name="fw-anchor" AND textPayload:"Sealed batch"'
if [ -n "${BILLING_ACCOUNT:-}" ]; then
  gcloud billing budgets create --billing-account "$BILLING_ACCOUNT" --display-name "fAIrewall Lab" \
    --budget-amount "${BUDGET_INR:-2000}INR" --threshold-rule percent=0.5 --threshold-rule percent=0.9 || true
fi

# ------------------------------------------------------------------ readiness
say "Readiness"
LAB_URL=$(gcloud run services describe fw-lab --region "$REGION" --format 'value(status.url)')
for i in $(seq 1 30); do curl -fs "$LAB_URL/healthz" >/dev/null && break; sleep 2; done
curl -fsS "$LAB_URL/api/status"; echo
echo
echo "fAIrewall Lab: $LAB_URL"
echo "Smoke checks:  LAB_URL=$LAB_URL ./deploy/gcp/smoke.sh"
