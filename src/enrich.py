def enrich(event: dict) -> dict:
    """
    Minimal enrichment:
    - environment tag
    - severity heuristic
    - signals/tags for detections
    """
    enriched = dict(event)
    enriched["environment"] = "demo"
    enriched["severity"] = "low"
    enriched["signals"] = []

    # CloudTrail: IAM changes are high signal
    if enriched.get("source") == "cloudtrail" and enriched.get("event_type") in {
        "CreateAccessKey",
        "AttachUserPolicy",
        "PutUserPolicy",
    }:
        enriched["severity"] = "high"
        enriched["signals"].append("iam_change")

    # Windows: PowerShell + encoded commands are high signal
    if enriched.get("source") == "windows":
        proc = (enriched.get("process") or "").lower()
        cmd = (enriched.get("command") or "").lower()

        if "powershell" in proc:
            enriched["severity"] = "medium"
            enriched["signals"].append("powershell_exec")

        if "-enc" in cmd or "encodedcommand" in cmd:
            enriched["severity"] = "high"
            enriched["signals"].append("encoded_powershell")

    # VPC flow: tag allowed traffic
    if enriched.get("source") == "vpc_flow" and enriched.get("action") == "ACCEPT":
        enriched["signals"].append("network_allowed")

    return enriched
