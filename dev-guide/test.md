## NetGuard AI – End-to-End Flow & Integration Guide

This document explains how the system works (frontend + backend) and how to test integrations in **local** and **production (Docker)** environments.

---

## 1. High-Level Architecture

- **Frontend**: React + Vite SPA in `frontend/`
  - Entry: `frontend/src/main.tsx`, `frontend/src/App.tsx`
  - Talks to backend through `/api/*` endpoints using `frontend/src/api.ts`.
- **Backend**: FastAPI service in `backend/app/`
  - Main app: `backend/app/main.py`
  - Uses MongoDB via `backend/app/db.py`.
  - Loads ML model via `backend/app/ml_inference.py`.
- **ML Pipeline**: Training code in `ml/train.py`
  - Produces artifacts in `ml/artifacts/` that the backend loads.
- **Data Store**: MongoDB
  - Collections: `logs`, `alerts`, `audit_logs`, `blocked_ips`.

---

## 2. Frontend Flow (What the User Sees)

### 2.1 App Start & Authentication

Files:
- `frontend/src/main.tsx`
- `frontend/src/App.tsx`

Flow:
1. App shows a brief **splash screen**.
2. It checks `localStorage` for `ng_user`.
3. If a user exists → navigates to **Dashboard**.
4. If no user → shows **Login** (and optional **Signup**).

### 2.2 Signup & Login Requests

File:
- `frontend/src/api.ts`

Endpoints called:
- **Signup**
  - `POST /api/signup`
  - Body: `{ full_name: string; email: string; password: string }`
  - Backend stores the user in an **in-memory** dict (demo only, not persistent).
- **Login**
  - `POST /api/login`
  - Body: `{ email: string; password: string }`
  - Backend returns:
    - `{ ok: boolean; token: string; user: { full_name: string; email: string } }`
  - Frontend stores `user` in `localStorage` under key `ng_user`.

### 2.3 Dashboard “Scan” (Simulated)

Dashboard component:
- `Dashboard` in `frontend/src/App.tsx`

API calls:
- Start scan: `POST /api/scan`
  - Response: `{ ok: true; session_id: string }`
- Poll progress: `GET /api/scan/{session_id}`
  - Response:
    - `status`: `"scanning"` or `"complete"`
    - `progress`: percentage 0–100
    - `result`: `{ device_name, device_ip, firewall_status, threats[], issues_found, system_status }`

Important:
- This **does not use the ML model**.
- Data is simulated in memory on the backend to give a live-looking scan experience.

### 2.4 History Page (Real Alerts or Demo Fallback)

History component:
- `History` in `frontend/src/App.tsx`

API call:
- `GET /api/history`

Backend behavior:
- If MongoDB has alerts, it:
  - Reads `alerts` collection and maps each record into a `HistoryItem` with:
    - `device_name`, `date_time`, `threats_identified`, `device_details`, `threats[]`.
- If there are **no alerts in MongoDB**, it:
  - Returns a static **demo list** so the UI always has something to show.

Result:
- History page shows either real alerts (after you run `/api/analyze`) or demo records.

---

## 3. Backend Flow (FastAPI)

Main file:
- `backend/app/main.py`

### 3.1 App Startup

- Uses a `lifespan` context manager:
  - Calls `ml_service.load()` from `backend/app/ml_inference.py`.
  - This loads:
    - `model.pkl`
    - `scaler.pkl`
    - `label_encoder.pkl`
    - `feature_names.json`
    - from the directory pointed to `NETGUARD_ARTIFACT_DIR` (default `ml/artifacts`).

### 3.2 MongoDB Access

File:
- `backend/app/db.py`

Key functions:
- `get_client()` / `get_db()` – connect to MongoDB using:
  - `MONGODB_URI` (default `mongodb://localhost:27017` or `mongodb://mongo:27017` in Docker)
  - `MONGODB_DB` (default `netguard_ai`)
- Collections:
  - `logs` – every `/api/analyze` request.
  - `alerts` – only when an attack exceeds the alert threshold.
  - `audit_logs` – email failures, analyst actions, block decisions, etc.
  - `blocked_ips` – records of IPs that have been blocked.

### 3.3 Important Endpoints

Health:
- `GET /api/health`
  - Returns:
    - `status`: `"ok"` or `"degraded"` (depending on MongoDB ping).
    - `mongodb`: boolean.
    - `model_loaded`: boolean.

Auth (demo, non-persistent):
- `POST /api/signup`
- `POST /api/login`
  - Use in-memory `_users` dict for demo logins.

Scan simulation:
- `POST /api/scan`
- `GET /api/scan/{session_id}`
  - Drive the Dashboard scan UI.

History:
- `GET /api/history`
  - Returns real alerts if they exist.
  - Otherwise returns static demo history.

ML inference (core of the threat detection):
- `POST /api/analyze`
  - Request body (`backend/app/schemas.py`):
    - `features: dict[str, Any]` – must include all names in `ml/artifacts/feature_names.json`.
    - `source_ip: str | null` – optional.
  - Processing steps:
    1. `ml_service.predict_from_features(features)`
       - Loads model & scaler if not loaded.
       - Ensures all feature names exist; raises `400` on missing features.
    2. Reads `alert_confidence_threshold` from settings (default `0.90` in `.env.example`).
    3. Determines `is_attack`:
       - `label != "Normal"`.
    4. Determines `should_alert`:
       - `is_attack` and `confidence >= threshold`.
    5. Writes to Mongo:
       - Insert log into `logs` (always).
       - Insert alert into `alerts` (only if `should_alert`).
    6. If `should_alert`:
       - Calls `send_attack_alert()` (email).
       - If email fails, writes an `audit_logs` entry with `action="email_alert_failed"`.
  - Response includes:
    - `label`, `confidence`, `probabilities`
    - `log_id`
    - `alert_id` (nullable)
    - `alert_triggered` (boolean)

Analyst actions:
- `POST /api/alert-action`
  - Body: `{ alert_id: string; action: "monitor" | "ignore" }`
  - Updates `alerts.analyst_status` and writes an `audit_logs` entry.

Firewall / IP blocking:
- `POST /api/block-ip`
  - Security:
    - Dependency `require_block_api_key()` enforces:
      - `Authorization: Bearer <BLOCK_API_KEY>`
  - Policy:
    - Uses `backend/app/ip_policy.py`:
      - Disallows:
        - Whitelisted IPs (`WHITELIST_IPS`).
        - Loopback addresses.
        - Private/link-local/reserved IPs unless `ALLOW_BLOCK_PRIVATE=true`.
  - Action:
    - If allowed and not already blocked:
      - Calls `apply_iptables_drop(ip)` (Linux-only).
      - Upserts into `blocked_ips`.
      - Writes `audit_logs` entry.
    - On non-Linux (e.g., Windows dev):
      - `iptables` step is skipped.
      - Block is recorded in DB with a message explaining why.

Listing endpoints:
- `GET /api/logs`
- `GET /api/alerts`
- `GET /api/blocked-ips`
- `GET /api/audit-logs`
- `GET /api/model-performance`
- `GET /api/analytics/summary`

---

## 4. ML Pipeline (How the Model Is Built)

Training entrypoint:
- `ml/train.py`

Inputs:
- Environment:
  - `EDGE_IIOTSET_CSV` (optional path to the Edge-IIoTset CSV).
  - If not set, defaults to: `data/sample_flow_features.csv`.
- Feature list:
  - From `shared/feature_columns.json` (shared with runtime inference).

Steps:
1. Load CSV (Edge-IIoTset or sample).
2. Auto-detect label column from a set of candidates (e.g., `attack_type`, `label`).
3. Normalize raw labels into one of:
   - `"Normal"`, `"DoS"`, `"DDoS"`, `"PortScan"`, `"Brute_Force"`.
4. Select features from `shared/feature_columns.json`.
5. Preprocess:
   - Numeric conversion.
   - Missing value imputation (median).
   - Standardization via `StandardScaler`.
6. Train `RandomForestClassifier` with class balancing.
7. Evaluate accuracy, F1, confusion matrix.
8. Write artifacts into `ml/artifacts/`:
   - `model.pkl`
   - `scaler.pkl`
   - `label_encoder.pkl`
   - `feature_names.json`
   - `model_metrics.json`

Runtime:
- Backend reads these artifacts at startup and uses the same feature ordering for inference.

---

## 5. Integration Test Guide – Local (For Developers)

This section is aimed at **engineers** running local integration tests.

### 5.1 Local Environment Prerequisites

- Python 3.12 (or compatible) and Node.js installed.
- MongoDB available at `mongodb://localhost:27017` (or adjust `MONGODB_URI`).
- Recommended: create a `.env` file from `.env.example` in the repo root.

Key values in `.env`:
- `MONGODB_URI=mongodb://localhost:27017`
- `MONGODB_DB=netguard_ai`
- `NETGUARD_ARTIFACT_DIR` (optional; if empty uses `ml/artifacts` relative to repo).
- `ALERT_CONFIDENCE_THRESHOLD` (e.g., `0.90`).
- SMTP variables if you want to test emails.
- `BLOCK_API_KEY` to test `/api/block-ip`.
- `CORS_ORIGINS` to match the Vite dev server URLs.

### 5.2 Step 1 – Build / Verify ML Artifacts

1. Install ML dependencies:
   - `pip install -r ml/requirements.txt`
2. Generate sample training data (if needed):
   - `python scripts/generate_sample_flow_data.py`
   - This writes `data/sample_flow_features.csv`.
3. Train the model:
   - `python ml/train.py`
   - Confirm that `ml/artifacts/` contains:
     - `model.pkl`
     - `scaler.pkl`
     - `label_encoder.pkl`
     - `feature_names.json`
     - `model_metrics.json`

### 5.3 Step 2 – Start Backend (Local)

1. Install backend dependencies:
   - `pip install -r backend/requirements.txt`
2. Ensure MongoDB is running locally.
3. Export environment variables (or load from `.env`).
4. Run FastAPI app (example with uvicorn):
   - `uvicorn app.main:app --host 0.0.0.0 --port 8000` from `backend/` (or with PYTHONPATH set appropriately).
5. Verify health:
   - `GET http://127.0.0.1:8000/api/health`
   - Expect:
     - `status: "ok"` (if Mongo reachable).
     - `mongodb: true`.
     - `model_loaded: true` (if artifacts exist).

### 5.4 Step 3 – Start Frontend (Local)

1. From `frontend/`:
   - `npm install`
   - `npm run dev`
2. By default, Vite dev server runs at:
   - `http://localhost:5173`
3. Proxy behavior (`frontend/vite.config.ts`):
   - Requests to `/api/*` are proxied to `http://127.0.0.1:8000`.
4. Confirm you can:
   - Open the UI at `http://localhost:5173`.
   - Sign up and log in (demo users only).
   - Run a Dashboard scan (simulated).

### 5.5 Step 4 – End-to-End ML Flow (Local)

Goal:
- Confirm that `/api/analyze` writes to Mongo and that `History` reflects real alerts.

Steps:
1. Ensure backend and MongoDB are running.
2. From repo root, run:
   - `python scripts/ingest_flow_to_api.py --url http://127.0.0.1:8000 --csv data/sample_flow_features.csv`
3. Observe:
   - Script outputs status codes and JSON from `/api/analyze`.
   - Backend logs show ML predictions and DB writes.
4. Open the frontend **History** page:
   - Expected:
     - Real entries based on the `alerts` collection.
     - If sample data triggers attacks above threshold, they should appear.

### 5.6 Step 5 – Block IP Integration (Local)

Note: On Windows/macOS, actual `iptables` commands are skipped, but the DB entries and audit logs are still created.

Steps:
1. Set `BLOCK_API_KEY` in backend env (or `.env`).
2. Call the API with a tool of your choice:
   - `POST http://127.0.0.1:8000/api/block-ip`
   - Headers: `Authorization: Bearer <BLOCK_API_KEY>`
   - JSON: `{ "ip": "203.0.113.10", "reason": "Test block", "analyst": "dev" }`
3. Expected:
   - Response with `ok: true`, possibly `firewall_applied: false` on non-Linux.
   - `blocked_ips` entry created in Mongo.
   - `audit_logs` entry with `action: "block_ip"` (or appropriate message if denied).

---

## 6. Integration Test Guide – Production / Docker (For Engineers & DevOps)

This section describes how the same flows work in a **Docker-based** environment, roughly representing production.

### 6.1 Docker Services Overview

File:
- `docker-compose.yml`

Services:
- `mongo`:
  - Image: `mongo:7`
  - Port: `27017:27017`
- `api`:
  - Builds from `backend/Dockerfile`.
  - Exposes port `8000`.
  - Environment:
    - `MONGODB_URI=mongodb://mongo:27017`
    - `MONGODB_DB=netguard_ai`
    - `BLOCK_API_KEY`
    - `CORS_ORIGINS`
    - `WHITELIST_IPS`
- `web`:
  - Builds from `frontend/Dockerfile`.
  - Serves static frontend via nginx on port `80` (mapped as `8080:80`).
  - nginx config (`frontend/nginx.conf`) proxies:
    - `/api/` → `http://api:8000/api/`

Backend Dockerfile (`backend/Dockerfile`):
- Copies:
  - `backend/app` to `/app/app`.
  - `ml/artifacts` to `/ml/artifacts`.
- Sets:
  - `NETGUARD_ARTIFACT_DIR=/ml/artifacts`.

Frontend Dockerfile (`frontend/Dockerfile`):
- Build stage:
  - Installs npm deps.
  - Accepts build args `VITE_API_BASE`, `VITE_BLOCK_API_KEY`.
  - Runs `npm run build`.
- Runtime stage:
  - Serves built app with nginx.
  - Delegates `/api/*` to backend service via nginx reverse proxy.

### 6.2 Build & Run Stack

From repo root:
1. Build images:
   - `docker compose build`
2. Start containers:
   - `docker compose up -d`

Once running:
- Backend API should be reachable at host port `8000`.
- Frontend web UI should be reachable at host port `8080`.

### 6.3 Production-Like End-to-End Test Steps

#### 6.3.1 Verify Backend Health

From your host:
- `GET http://localhost:8000/api/health`
- Expect:
  - `mongodb: true` (if container `mongo` is healthy).
  - `model_loaded: true` (if artifacts bundled correctly).

#### 6.3.2 Open Frontend

- Visit: `http://localhost:8080/`
- Confirm:
  - You can sign up and log in.
  - Dashboard and History pages load without CORS issues (should be covered by nginx and CORS config).

#### 6.3.3 Trigger Real ML Inference in Docker

From host (using the API):
- Run:
  - `python scripts/ingest_flow_to_api.py --url http://localhost:8000 --csv data/sample_flow_features.csv`

Expected:
- The script posts to `http://localhost:8000/api/analyze`.
- Backend inside the `api` container:
  - Uses `/ml/artifacts` for model/scaler/encoder.
  - Writes `logs` and `alerts` to the `mongo` container.
- The `History` page at `http://localhost:8080` should now show real entries sourced from MongoDB.

#### 6.3.4 Test `block-ip` in Docker

1. Ensure `BLOCK_API_KEY` is set in `docker-compose.yml` or your environment.
2. From host, call:
   - `POST http://localhost:8000/api/block-ip`
   - Headers: `Authorization: Bearer <BLOCK_API_KEY>`
   - Body: `{ "ip": "198.51.100.25", "reason": "Suspected test attack", "analyst": "qa" }`
3. On a Linux Docker host:
   - The container tries `iptables -A INPUT -s <ip> -j DROP` via `sudo`.
   - If success, `firewall_applied: true` and an audit log is stored.
4. On non-Linux hosts, or if `iptables` is not available:
   - `firewall_applied: false` with a descriptive message.
   - `blocked_ips` and `audit_logs` are still updated.

### 6.4 Email Alert Testing in Docker

Optional but recommended for full integration coverage:

1. Configure SMTP environment variables on the `api` service:
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO`, `SMTP_USE_TLS`.
2. Restart the stack:
   - `docker compose up -d --force-recreate --build api`
3. Run `/api/analyze` again via:
   - `scripts/ingest_flow_to_api.py` or manual POST.
4. For alerts where:
   - `label != "Normal"` and `confidence >= ALERT_CONFIDENCE_THRESHOLD`:
   - The backend attempts to send email.
5. If email fails:
   - An entry with `action="email_alert_failed"` appears in `audit_logs`.

---

## 7. Manual QA Scenario Guide (Step-by-Step)

This section is written for **QA testers** who may not be deep into the code.

### 7.1 Local QA – Basic App Checks

Precondition:
- A developer has already started the **backend** on `http://127.0.0.1:8000` and the **frontend** on `http://localhost:5173`.

Steps:
1. Open `http://localhost:5173` in a browser.
2. Wait for the splash screen to complete; you should be taken to the **Login** page.
3. Click **“Need an account? Sign up”**:
   - Enter a **Full Name**, a valid **Email**, and a **Password ≥ 6 chars**.
   - Accept the terms checkbox.
   - Click **SIGN UP**.
   - Then log in with the same email + password.
4. After login, verify:
   - You are on the **Dashboard**.
   - The **System Status**, **AI Analysis**, and **Alerts** tiles show some values.
5. Click **Start Scan**:
   - A progress bar should animate from 0% to 100%.
   - Once complete, the **System Status** and threats section should update (may show “Secure” or some threats).

### 7.2 Local QA – History Page

1. From the left sidebar, click the **History** icon/button (H).
2. Confirm:
   - A table of **Device Name**, **Date & Time**, **Threats**, **Details**.
3. If sample alerts are loaded:
   - Click **View** on any row under **Details**.
   - You should see record details with:
     - IP address.
     - Firewall status.
     - Threat list (name, type, time).
4. If no real alerts were ingested, you may see demo history entries; behavior is still considered valid for UI.

### 7.3 Docker / Production-Like QA

Precondition:
- A developer or DevOps engineer has:
  - Run `docker compose up -d`.
  - Confirmed containers are healthy.

Steps:
1. In a browser, open `http://localhost:8080`.
2. Repeat the same **Signup/Login**, **Dashboard**, and **History** checks as in local QA.
3. Optionally coordinate with a developer to:
   - Run the ingestion script against the Docker backend:
     - `python scripts/ingest_flow_to_api.py --url http://localhost:8000 --csv data/sample_flow_features.csv`
   - Then refresh the **History** page to confirm new entries appear based on real ML predictions.

---

## 8. Quick Checklists

### 8.1 Developer Sanity Checklist (Local)

- **ML Artifacts**:
  - `ml/train.py` has been run and artifacts exist in `ml/artifacts/`.
- **Backend**:
  - `GET /api/health` shows `model_loaded: true`.
- **Frontend**:
  - Dev server runs at `http://localhost:5173` with no CORS errors.
- **End-to-End**:
  - `scripts/ingest_flow_to_api.py` populates Mongo.
  - `GET /api/history` returns entries from Mongo.
  - History page in UI shows non-demo entries.

### 8.2 QA Sanity Checklist

- Can create a new account and log in.
- Dashboard scan runs to 100% and updates status.
- History table appears and **View** shows record details.
- In Docker-based environment, behavior is the same at `http://localhost:8080`.

