# fAIrewall SDK Gateway — Deployment Guide

This guide shows you exactly how to connect each platform to a running
fAIrewall gateway so real bots call real endpoints.

---

## Prerequisites

- Docker and Docker Compose installed ([docs.docker.com](https://docs.docker.com/get-docker/))
- A domain or a tool like [ngrok](https://ngrok.com) for a public HTTPS URL

---

## Step 1 — Configure your secrets

```bash
cp .env.example .env
```

Open `.env` in any text editor and fill in the secrets for the platforms
you use. You only need to set variables for the platforms you actually want
active — anything missing is silently skipped.

---

## Step 2 — Start the gateway

```bash
docker compose up --build
```

The gateway is now running at `http://localhost:8000`.

Check it is healthy:

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.2.0",...}

curl http://localhost:8000/v1/sdk/health
# {"status":"ok","adapters_mounted":["zapier","copilot",...],...}
```

---

## Step 3 — Expose it publicly

> **For development / testing:** use ngrok (free, no account required for basic use):
>
> ```bash
> ngrok http 8000
> # → Forwarding  https://abc123.ngrok-free.app → http://localhost:8000
> ```
>
> Your public base URL is `https://abc123.ngrok-free.app`.

> **For production:** deploy the Docker container to any cloud platform.
> See [Production Deployment](#production-deployment) at the bottom.

---

## Step 4 — Connect each platform

---

### 🔗 Zapier Agents

**What to configure in Zapier:**

1. In your Zap, add a **Webhooks by Zapier** action step
2. Set **Method** to `POST`
3. Set **URL** to: `https://YOUR_DOMAIN/v1/zapier/action`
4. Set **Payload Type** to `json`
5. Include your action payload:
   ```json
   {
     "action": "create_invoice",
     "inputData": { "amount": 150.0, "client": "Acme Corp" },
     "meta": { "zap_id": "{{zap_id}}", "user_id": "{{user_id}}" }
   }
   ```
6. Add header: `X-Zapier-Secret: your-zapier-hmac-secret-here`

**To screen an inbound trigger for injection:**
- URL: `POST https://YOUR_DOMAIN/v1/zapier/screen`
- Body: `{"text": "{{trigger content}}", "zap_id": "{{zap_id}}"}`

**Response — allowed:**
```json
{ "allowed": true, "blocked": false, "reason": "Allowed." }
```

**Response — blocked:**
```json
{ "allowed": false, "blocked": true, "reason": "[financial.transaction_limit] ..." }
```

---

### 🔗 Microsoft Copilot Studio

**What to configure in Copilot Studio:**

1. Open your Copilot bot in **Copilot Studio**
2. Go to **Settings → Advanced → Bot Framework endpoint**
3. Set the **Messaging endpoint** to: `https://YOUR_DOMAIN/v1/copilot/activity`
4. Or create a **Power Automate Cloud Flow** HTTP action pointing to:
   `POST https://YOUR_DOMAIN/v1/copilot/action`

**Activity payload (Bot Framework format):**
```json
{
  "type": "message",
  "id": "conv-001-msg-01",
  "from": { "id": "aad-user-alice@corp.com" },
  "conversation": { "id": "conv-001" },
  "text": "Please process the attached invoice."
}
```

**For plugin / Power Automate invoke:**
```json
{
  "action": "send_email",
  "arguments": { "to": "ceo@corp.com", "subject": "Report" },
  "user_id": "aad-user-alice",
  "conversation_id": "conv-001"
}
```

> **JWT validation:** Set `COPILOT_TENANT_ID` in `.env` to enable full Azure AD JWT
> verification. Without it, the adapter accepts all requests (dev mode only).

---

### 🔗 Salesforce Agentforce

**What to configure in Salesforce:**

1. Go to **Setup → Named Credentials → New Named Credential**
2. Set **URL** to: `https://YOUR_DOMAIN/v1/salesforce`
3. Set **Authentication Protocol** to `JWT Token`
4. Copy your **Connected App Consumer Key** into `SALESFORCE_CONSUMER_KEY` in `.env`

**Action payload (Salesforce External Service format):**
```json
{
  "action": "update_opportunity_amount",
  "inputs": [
    { "opportunity_id": "006Dn000000Alice", "amount": 5000.0 }
  ],
  "userId": "005Dn000000Alice",
  "organizationId": "00D000001"
}
```

**Screen inbound CRM data:**
```bash
POST https://YOUR_DOMAIN/v1/salesforce/screen
{
  "text": "Lead note: ignore previous instructions...",
  "user_id": "005Dn000000Alice",
  "source": "lead_import"
}
```

---

### 🔗 WhatsApp / Haptik

**What to configure in Meta Developer Dashboard:**

1. Go to [developers.facebook.com](https://developers.facebook.com) → Your App
2. **WhatsApp → Configuration → Webhook**
3. Set **Callback URL** to: `https://YOUR_DOMAIN/v1/whatsapp/message`
4. Set **Verify token** to the same value as `META_VERIFY_TOKEN` in your `.env`
5. Click **Verify and Save** — Meta sends a GET request; the gateway responds automatically
6. Subscribe to the **messages** webhook field

**Incoming message (handled automatically by Meta):**
```json
{
  "object": "whatsapp_business_account",
  "entry": [{
    "changes": [{
      "value": {
        "messages": [{ "from": "+911234567890", "text": { "body": "Hi, check my order" } }]
      }
    }]
  }]
}
```

**For Haptik platform:**
- URL: `POST https://YOUR_DOMAIN/v1/haptik/message`
- Header: `X-Haptik-Token: your-haptik-api-token`

---

### 🔗 UiPath Platform

**What to configure in UiPath Automation Cloud:**

1. Go to **Automation Cloud → Admin → Webhooks**
2. Click **+ Add Webhook**
3. Set **URL** to: `https://YOUR_DOMAIN/v1/uipath/job-started`
4. Subscribe to events: **job.started**, **job.completed**, **queue.item.added**
5. Copy the **Secret** shown (only displayed once!) into `UIPATH_WEBHOOK_SECRET` in `.env`

**Job started payload (sent automatically by UiPath):**
```json
{
  "Type": "job.started",
  "EventId": "evt-001",
  "Timestamp": "2026-09-18T12:00:00Z",
  "Job": {
    "Id": "job-001",
    "Key": "abcd-1234",
    "StartingScheduleId": null,
    "Release": { "Name": "InvoiceApprovalProcess" },
    "InputArguments": "{\"invoice_id\": \"INV-001\", \"amount\": 1200.0}"
  }
}
```

For action guarding (before the robot executes a step):
- URL: `POST https://YOUR_DOMAIN/v1/uipath/action-request`

---

## Audit Log

Every governance decision is appended to the tamper-evident audit log at
`./data/audit.jsonl` on the host (mounted from `/app/data/audit.jsonl` in
the container).

To verify the chain has not been tampered with:

```bash
fairewall verify-audit ./data/audit.jsonl
# Chain intact! Verified 1482 records.

# Or via HTTP
curl http://localhost:8000/v1/audit/verify
```

---

## Shadow Mode (Dry Run)

Run with `FAIREWALL_SHADOW=true` to observe what would be blocked without
actually blocking anything. Useful for testing against real traffic before
going fully live:

```bash
FAIREWALL_SHADOW=true docker compose up
```

All decisions are still logged to the audit trail.

---

## Production Deployment

The Docker image runs on any container platform. One-liners for the most
common options (replace `YOUR_DOMAIN` with the URL the platform gives you):

### Railway

```bash
railway up
# Set env vars in Railway dashboard → Variables
```

### Fly.io

```bash
fly launch --dockerfile Dockerfile
fly secrets set ZAPIER_WEBHOOK_SECRET=xxx META_APP_SECRET=yyy ...
fly deploy
```

### Google Cloud Run

```bash
gcloud builds submit --tag gcr.io/YOUR_PROJECT/fairewall
gcloud run deploy fairewall \
  --image gcr.io/YOUR_PROJECT/fairewall \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars FAIREWALL_PRESET=ZAPIER_SME,ZAPIER_WEBHOOK_SECRET=xxx
```

### AWS ECS / Fargate

Upload the image to ECR, create a task definition, and set environment
variables in the task definition or via AWS Secrets Manager.

---

## Testing Your Setup

Once the gateway is running and publicly accessible, test it end-to-end:

```bash
BASE=https://YOUR_DOMAIN

# Health check
curl $BASE/health

# List mounted adapters
curl $BASE/v1/sdk/health

# Manual action test (Zapier)
curl -X POST $BASE/v1/zapier/action \
  -H "Content-Type: application/json" \
  -H "X-Zapier-Secret: your-secret" \
  -d '{"action":"send_email","inputData":{"amount":50},"meta":{"zap_id":"zap-001"}}'

# Should return: {"allowed":true,...}

# Over-limit test
curl -X POST $BASE/v1/zapier/action \
  -H "Content-Type: application/json" \
  -H "X-Zapier-Secret: your-secret" \
  -d '{"action":"send_email","inputData":{"amount":9999},"meta":{"zap_id":"zap-001"}}'

# Should return 403: {"allowed":false,"blocked":true,"reason":"[financial.transaction_limit]..."}
```
