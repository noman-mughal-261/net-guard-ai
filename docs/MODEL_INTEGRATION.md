# Integrating your trained model (`netguard_rf_model.pkl`)

The API loads **four artifacts** from one directory. They must come from the **same training pipeline**: the scaler and label encoder must match the data the forest was fit on.

| File | Role |
|------|------|
| Classifier | `model.pkl` by default, or any name via `NETGUARD_MODEL_FILENAME` (e.g. `netguard_rf_model.pkl`) |
| `scaler.pkl` | `StandardScaler` (or compatible) — same as training |
| `label_encoder.pkl` | `LabelEncoder` for class names |
| `feature_names.json` | Ordered list of feature column names (same order as training) |

Optional: `model_metrics.json` for `/api/model-performance` (not required for inference).

## 1. Prepare a single artifact folder

On your machine, create a folder (for example `C:\models\netguard`) and copy:

1. Your `netguard_rf_model.pkl` (the `RandomForestClassifier` or object with `predict_proba`).
2. `scaler.pkl`, `label_encoder.pkl`, and `feature_names.json` from **that same training run**.

If you only have the `.pkl` forest and no scaler/encoder, you cannot drop them in arbitrarily: you must re-save them from the notebook/script that trained the model, or re-run training with this repo’s `ml/train.py` so all four files are produced together.

This project’s canonical feature list is `shared/feature_columns.json` (flow statistics). Your `feature_names.json` should list the same names in the same order your model expects.

## 2. Point the backend at that folder

### Local (no Docker)

PowerShell:

```powershell
$env:NETGUARD_ARTIFACT_DIR = "C:\path\to\your\artifact\folder"
$env:NETGUARD_MODEL_FILENAME = "netguard_rf_model.pkl"
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Docker Compose

Either bake files into the image under `/ml/artifacts`, or mount your host folder:

```yaml
api:
  volumes:
    - C:/path/to/your/artifact/folder:/ml/artifacts:ro
  environment:
    NETGUARD_ARTIFACT_DIR: /ml/artifacts
    NETGUARD_MODEL_FILENAME: netguard_rf_model.pkl
```

Adjust the host path for your OS.

## 3. Verify artifacts before starting

From the repository root (with Python available):

```powershell
python scripts/check_ml_artifacts.py "C:\path\to\your\artifact\folder" --model-filename netguard_rf_model.pkl
```

Or set `NETGUARD_ARTIFACT_DIR` and run with no positional argument.

## 4. First inference test

1. Start MongoDB (required for `/api/analyze` logging), e.g. `docker compose up mongo` or a local `mongod`.
2. Start the API as in step 2.
3. Health check: `GET http://localhost:8000/api/health` — `model_loaded` should be `true`.
4. Run unit tests (after `ml/train.py` has populated `ml/artifacts`, or with your folder + env vars):

```powershell
cd backend
pip install -r requirements.txt
$env:NETGUARD_ARTIFACT_DIR = "C:\path\to\your\artifact\folder"
$env:NETGUARD_MODEL_FILENAME = "netguard_rf_model.pkl"
pytest tests/test_ml_inference.py -v
```

5. Optional API smoke test (Mongo must be running): send a JSON body whose `features` object contains every key in `feature_names.json` (values are numbers). Example shape:

```json
{
  "source_ip": "192.0.2.1",
  "features": {
    "flow_duration": 100.0,
    "tot_fwd_pkts": 10.0
  }
}
```

You must include **all** feature keys; missing keys are rejected with `400`.

## 5. Rename instead of env var

If you prefer not to set `NETGUARD_MODEL_FILENAME`, copy or rename your file to `model.pkl` inside the artifact directory.

## Troubleshooting

- **`Missing model artifacts` on startup**: Run `scripts/check_ml_artifacts.py` and fix any `MISSING` lines.
- **`Inference error` / shape mismatch**: `feature_names.json` order or length does not match training, or scaler was not the one used for this model.
- **`model_loaded: false` in health**: Startup `load()` failed; check API logs for the `FileNotFoundError` message.

## Full stack test (Docker)

The API image **trains a demo model at build time** from `data/sample_flow_features.csv`, so `docker compose up --build` has a working classifier without copying local `.pkl` files.

From the repository root:

```powershell
.\scripts\e2e_test.ps1
```

This brings up **mongo**, **api**, and **web**, waits until `/api/health` reports Mongo and the model, runs HTTP checks (including `POST /api/analyze` using `data/sample_single_flow.json` and an optional frontend `GET`), then runs `docker compose down`.

Without PowerShell (or to hit an already-running API):

```bash
docker compose up --build -d
# wait until healthy, then:
python scripts/e2e_test.py --base-url http://127.0.0.1:8000 --frontend-url http://127.0.0.1:8080
docker compose down
```

Backend unit tests (no Docker): from `backend/`, run `pytest tests/ -v`.
