# FedRAMP / NIST 800-53 Control Mapping

This project simulates a cloud-native SIEM pipeline designed to support
logging, monitoring, and incident detection requirements in regulated
environments (e.g., FedRAMP Moderate).

## Relevant Controls

### AU-2 – Event Logging
- Ingests CloudTrail, Windows Security Events, and VPC Flow Logs
- Normalizes events into a consistent schema for auditability

### AU-6 – Audit Review, Analysis, and Reporting
- Implements baseline detections for:
  - IAM access key creation
  - Encoded PowerShell execution
  - High-volume network flows
- Produces structured alert output (`alerts.jsonl`) for analyst review

### AU-12 – Audit Generation
- Automatically generates enriched audit records with:
  - Severity
  - Signals/tags
  - Environment context

### IR-5 – Incident Monitoring
- Detection logic supports early identification of:
  - Credential abuse
  - Suspicious host activity
  - Network anomalies

## Notes
This implementation focuses on detection and monitoring logic.
Retention, encryption-at-rest, and access control would typically be
handled by underlying platform services in a production deployment.

