from typing import List, Dict


def detect(event: Dict) -> List[Dict]:
    """
    Return a list of alert dictionaries generated from a single event.
    """
    alerts: List[Dict] = []

    source = event.get("source")
    signals = set(event.get("signals", []))

    # Detection 1: IAM Access Key creation
    if source == "cloudtrail" and event.get("event_type") == "CreateAccessKey":
        alerts.append(
            {
                "rule": "IAM Access Key Created",
                "severity": "high",
                "reason": f"Access key created for user={event.get('user')}",
                "event_time": event.get("time"),
                "source": source,
            }
        )

    # Detection 2: Encoded PowerShell execution
    if source == "windows" and "encoded_powershell" in signals:
        alerts.append(
            {
                "rule": "Encoded PowerShell Execution",
                "severity": "high",
                "reason": f"Encoded PowerShell observed for user={event.get('user')}",
                "event_time": event.get("time"),
                "source": source,
            }
        )

    # Detection 3: High-volume VPC Flow
    if source == "vpc_flow":
        try:
            bytes_val = int(event.get("bytes", "0"))
        except ValueError:
            bytes_val = 0

        if bytes_val > 5000:
            alerts.append(
                {
                    "rule": "High Volume Network Flow",
                    "severity": "medium",
                    "reason": f"bytes={bytes_val} src={event.get('src_ip')} dst={event.get('dst_ip')}",
                    "event_time": event.get("time"),
                    "source": source,
                }
            )

    return alerts
