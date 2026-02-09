# RapidCallAI API (Node.js / Express)

This is the backend API for RapidCallAI.

It:
- Stores **Agents** and **Calls** in **Postgres (AWS RDS)**.
- Creates LiveKit rooms + participant tokens.
- Starts/stops **LiveKit Egress** recordings to **S3**.
- Receives per-call **metrics** (tokens/latency/cost) posted by the Python agent.

## Requirements

- Node 20+ (local)
- Docker (production on EC2)
- Postgres (AWS RDS recommended)
- LiveKit Cloud project credentials
- S3 bucket + IAM credentials for egress

## Environment

Copy `env.example` → `.env` and fill values.

Critical variables:

- `LIVEKIT_URL`, `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`
- `DATABASE_URL` (points to your RDS database, e.g. `...:5432/rapidcallai`)
- `DATABASE_SSL=true` (keep true for RDS)
- `CLIENT_ORIGIN` (your dashboard URL)
- `EGRESS_S3_*` for recordings

## Local development

```bash
npm install
npm run dev
```

Health check:

```bash
curl -s http://localhost:8787/health
```

## Production deployment (EC2 + Docker Compose + Caddy)

Your EC2 layout (recommended):

```
/opt/rapidcallai/
  docker-compose.yml
  Caddyfile
  api/        (this repo)
  dashboard/  (rapidcallai-dashboard repo)
```

### Update flow (most common)

1) SSH into EC2.
2) Pull latest code for API and rebuild container.

```bash
cd /opt/rapidcallai/api
git pull

cd /opt/rapidcallai
docker compose up -d --build api
docker compose logs --tail=120 api
```

### Verify the API is using Postgres (not JSON fallback)

Check API boot logs:
- You want: `Postgres: schema ready.`
- If you see: `DATABASE_URL not set; falling back...` then it is NOT using Postgres.

```bash
cd /opt/rapidcallai
docker compose logs --tail=200 api
```

### View the real server console

```bash
cd /opt/rapidcallai
docker compose logs -f --tail=200 api
```

### Run the one-time JSON → Postgres import (optional)

Only needed if you had previous JSON data (`data/agents.json`, `data/calls.json`).

```bash
cd /opt/rapidcallai
docker compose run --rm api node src/migrate_from_json.js
```

If the API container is crash-looping, prefer `docker compose run --rm ...` over `docker compose exec ...`.

## LiveKit + Egress notes

### Recordings

Recordings are produced by LiveKit Egress and uploaded to:

```
s3://$EGRESS_S3_BUCKET/calls/<callId>.mp3
```

The API streams recordings via:

```
GET /api/calls/:id/recording
```

### Metrics

The Python agent posts metrics to:

```
POST /api/calls/:callId/metrics
```

### Inbound calls (no answer / no voice)

For inbound calls to work you need:

1. **LiveKit Cloud dispatch rule**  
   In LiveKit Cloud → your project → SIP → Inbound → create a **dispatch rule** for your inbound trunk (room prefix e.g. `call-`) so that when a call arrives, LiveKit creates a room and dispatches your agent. Without this, Twilio may ring until timeout and never get answered.

2. **Agent env so it can reach the API and get dispatched**  
   The Python agent must have:
   - `SERVER_BASE_URL` (or `PUBLIC_API_BASE_URL`) = your API base URL (e.g. `https://api.rapidcall.ai`)
   - `AGENT_SHARED_SECRET` = same value as on the API (required for `/api/internal/telephony/inbound/start`)
   - `LIVEKIT_AGENT_NAME=VoiceAgent` (or whatever name your dispatch rule uses under “Agents”) so LiveKit dispatches this agent to the room.

3. **Inbound agent set in Dashboard (recommended)**  
   In Phone Numbers, open the number and set **Inbound agent** to your voice agent. If this is not set, the API returns a fallback prompt and the agent will say “This number is not configured for inbound calls…”; set it to get your real agent prompt and voice.

**Important — numbers on the SIP trunk:**  
When a phone number is associated with the Twilio SIP trunk (for outbound), Twilio **ignores** that number’s “Voice URL”. Inbound calls go straight to the trunk’s **Origination URI** (your LiveKit SIP endpoint). So you will **not** see `[twilio-inbound]` in API logs for those calls. You will see `[internal.telephony.inbound.start]` when the agent joins and calls the API. Audio depends on: LiveKit dispatch rule, agent env (`SERVER_BASE_URL`, `AGENT_SHARED_SECRET`, `LIVEKIT_AGENT_NAME`), and (optionally) Inbound agent set in the dashboard.

**After migrating to a new Twilio account:**

1. Run **Reprovision** for each phone number (Dashboard → Phone Numbers → ⋮ → Reprovision) so the new account’s trunk, origination URI, and LiveKit trunks are correct.
2. In Twilio Console → Elastic SIP Trunking → your trunk → **Origination**: confirm the URI is `sip:YOUR_LIVEKIT_SIP_ENDPOINT;transport=tls` (e.g. `sip:25f6q0vix3k.sip.livekit.cloud;transport=tls`).
3. Ensure the Python agent has the correct `SERVER_BASE_URL`, `AGENT_SHARED_SECRET`, and `LIVEKIT_AGENT_NAME` (must match the dispatch rule’s “Agents” field).
4. Place a test inbound call and watch API logs for `[internal.telephony.inbound.start]`. If that line appears but you still get no voice, the issue is likely agent dispatch or RTP/audio; if it never appears, the agent may not be joining or cannot reach the API.

**Calling from Europe (or any international number):**  
No impact. Twilio accepts callers from any country; the “From” number (e.g. +371…) is just caller ID. Inbound routing and audio depend on your trunk/origination and agent, not the caller’s region.

API logs to check: `[internal.telephony.inbound.start]` (agent requested config). For numbers *not* on a trunk you may also see `[twilio-inbound] dial`. If you hear the fallback message, set the Inbound agent on the number in the dashboard.

## Observability (recommended for production)

**Structured logs (JSON):**
- Install `pino` + `pino-http` and set `LOG_LEVEL=info`

**Alerting:**
- Set `ALERT_WEBHOOK_URL` to receive billing/egress failure alerts

## Security & secrets rotation (recommended)

**Secrets to rotate regularly:**
- `AGENT_SHARED_SECRET`
- `LIVEKIT_API_KEY` / `LIVEKIT_API_SECRET`
- `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET`
- `TWILIO_AUTH_TOKEN`
- `EGRESS_S3_ACCESS_KEY` / `EGRESS_S3_SECRET`

**Rotation plan:**
1) Create a new secret in the provider (Stripe/Twilio/LiveKit/AWS).
2) Add the new secret to your `.env` (or secret manager) **alongside** the old one.
3) Deploy the API/agent with both secrets temporarily supported.
4) Verify new traffic works (logins, calls, webhooks).
5) Remove the old secret and redeploy.

**Tip:** Keep a calendar reminder (monthly or quarterly) and log each rotation.

## Troubleshooting

### Nothing in API logs when I make an inbound call

If **no line appears** in the API logs when you call your number, the request from the agent to your API never reaches the server. The flow is: **Twilio → LiveKit (Origination) → room created → dispatch rule runs → agent joins → agent calls your API**. So "nothing in log" usually means either the **agent is not being dispatched** or the **agent cannot reach the API**.

**1. Confirm the API is reachable from the agent**

From the **same machine (or network) where the Python agent runs**, run (replace URL and secret):

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST "https://api.rapidcall.ai/api/internal/telephony/inbound/start" \
  -H "Content-Type: application/json" \
  -H "x-agent-secret: YOUR_AGENT_SHARED_SECRET" \
  -d '{"roomName":"test","to":"+17073808675","from":"+3710000000"}'
```

- If you see **201** and a log line like `[internal.telephony.inbound.start] request received`, the API is reachable and the problem is that the **agent is not being dispatched** when you call.
- If you see **401**, the secret is wrong: `AGENT_SHARED_SECRET` on the API and on the agent must match exactly.
- If you see **connection refused / timeout / no route**, the agent host cannot reach the API (firewall, wrong `SERVER_BASE_URL`, or DNS).

**2. Confirm the agent is running and registered**

- The agent must be **running** and connected to LiveKit.
- It must register with the **same name** as in your LiveKit dispatch rule (e.g. `LIVEKIT_AGENT_NAME=VoiceAgent` if the rule's "Agents" is `VoiceAgent`).
- When the agent is dispatched you should see in **agent logs**: `Job received for room call-...`. If you never see that when you call, LiveKit is not dispatching the agent (see dispatch rule checklist below).

**Dispatch rule checklist (agent never joins)**

In **LiveKit Cloud** → your project → **Telephony** → **Dispatch rules** ([docs](https://docs.livekit.io/telephony/accepting-calls/dispatch-rule/)):

- **Trunk match:** The rule must apply to the trunk that receives the call. Your number is on an **inbound trunk** (e.g. `ST_fcSgRLMVYMDQ`). Either set the rule to "All numbers and trunks" or include that trunk ID in the rule’s **Trunks**. If the rule only matches a different trunk, the agent will not be dispatched.
- **Agent name:** The rule’s **Room configuration** → **Agents** must list an `agentName` that **exactly** matches `LIVEKIT_AGENT_NAME` in the Python agent (e.g. `VoiceAgent`). Case-sensitive.
- **Room prefix:** For "Caller (individual)" rules, the room name will be like `call-+1234567890-xxxx`. The rule’s room prefix (e.g. `call-`) must match how rooms are created.

**3. Confirm LiveKit creates a room and dispatches**

- In **LiveKit Cloud** → your project → **Rooms** (or SIP / call logs), check whether a **room** is created when you place the call.
- If no room is created, Twilio may not be sending the call to LiveKit (check **Origination URI** on the Twilio trunk).
- If a room is created but no agent joins, the **dispatch rule** may not match (trunk, room prefix, or agent name).

After deploying the latest API, you will see at least `[internal.telephony.inbound.start] request received` for **every** POST to that URL (including failed auth). If you still see nothing when you call, the agent is not calling the API — fix dispatch and agent connectivity first.

### Twilio "trunking issue" / agent doesn't connect on inbound

If Twilio reports a trunking error when you call your number, or the call never reaches the agent:

1. **Check inbound diagnostics** (Dashboard logged in, or with a valid session):
   ```bash
   curl -s -H "Authorization: Bearer YOUR_JWT" "https://api.rapidcall.ai/api/workspaces/YOUR_WORKSPACE_ID/inbound-diagnostics"
   ```
   Look at `LIVEKIT_SIP_ENDPOINT`, `originationUrls`, and `expectedOriginationSipUrl`. If `originationUrls` is empty or doesn't match `expectedOriginationSipUrl`, the Twilio trunk has no (or wrong) origination and inbound will fail.

2. **Set `LIVEKIT_SIP_ENDPOINT`** on the API server (e.g. in `.env`): your LiveKit SIP host only, e.g. `25f6q0vix3k.sip.livekit.cloud` (no `sip:` or port). Restart the API.

3. **Run Reprovision** for the phone number (Dashboard → Phone Numbers → ⋮ → Reprovision). Watch API logs for `[reprovision-outbound] Setting Twilio trunk origination for inbound: sip:...;transport=tls` and `✓ Origination URI set`. If you see `LIVEKIT_SIP_ENDPOINT is not set`, set it and reprovision again.

4. Call the diagnostics URL again and confirm `originationUrls` now contains the expected URI. Then place a test inbound call.

### "database does not exist"

Your `DATABASE_URL` points to a DB name that hasn’t been created yet.

Create it (example):

```bash
sudo apt-get update -y
sudo apt-get install -y postgresql-client
psql "postgresql://postgres:<password>@<rds-endpoint>:5432/postgres" -c "CREATE DATABASE rapidcallai;"
```

### Container keeps restarting

```bash
cd /opt/rapidcallai
docker compose ps
docker compose logs --tail=300 api
```

### Rebuild from scratch (API only)

```bash
cd /opt/rapidcallai
docker compose build --no-cache api
docker compose up -d --force-recreate api
```


