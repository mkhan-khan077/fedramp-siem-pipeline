# FedRAMP-Style SIEM Pipeline (Normalization + Enrichment + Detections)

A reference implementation of a cloud logging pipeline for regulated environments. The pipeline ingests sample telemetry
(CloudTrail, VPC Flow Logs, Windows events), normalizes records into a common schema, enriches context, and produces
baseline security detections with alert outputs.

## Architecture
See `docs/architecture.md`.

## Run locally
```bash
python -m src.main

## Example alerts
Run `python3 -m src.main` and view alerts in `outputs/alerts.jsonl`.

Example:
```json
{"rule":"IAM Access Key Created","severity":"high","reason":"Access key created for user=test-user","event_time":"2025-01-10T18:45:12Z","source":"cloudtrail"}


Then:
```bash
git add README.md
git commit -m "Document example alert output"
git push
