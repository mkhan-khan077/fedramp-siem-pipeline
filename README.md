# FedRAMP-Style SIEM Pipeline (Normalization + Enrichment + Detections)

A reference implementation of a cloud logging pipeline for regulated environments. The pipeline ingests sample telemetry
(CloudTrail, VPC Flow Logs, Windows events), normalizes records into a common schema, enriches context, and produces
baseline security detections with alert outputs.

## Architecture
See `docs/architecture.md`.

## Run locally
```bash
python -m src.main