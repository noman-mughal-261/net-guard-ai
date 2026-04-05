FROM python:3.12-slim AS trainer

WORKDIR /build

COPY ml/requirements.txt ml/requirements.txt
RUN pip install --no-cache-dir -r ml/requirements.txt

COPY ml/train.py ml/train.py
COPY shared shared
COPY data/sample_flow_features.csv data/sample_flow_features.csv

RUN mkdir -p ml/artifacts \
    && python ml/train.py --csv data/sample_flow_features.csv --out ml/artifacts

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends sudo iptables \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=trainer /build/ml/artifacts /ml/artifacts

ENV NETGUARD_ARTIFACT_DIR=/ml/artifacts
ENV NETGUARD_MODEL_FILENAME=model.pkl
ENV MONGODB_URI=mongodb://mongo:27017

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
