import json


def normalize_cloudtrail(record: dict) -> dict:
    return {
        "time": record.get("eventTime"),
        "source": "cloudtrail",
        "event_type": record.get("eventName"),
        "user": record.get("userIdentity", {}).get("userName"),
        "src_ip": record.get("sourceIPAddress"),
        "status": "success",
        "raw": record,
    }


def normalize_windows(record: dict) -> dict:
    return {
        "time": record.get("TimeCreated"),
        "source": "windows",
        "event_type": str(record.get("EventID")),
        "user": record.get("User"),
        "process": record.get("ProcessName"),
        "command": record.get("CommandLine"),
        "raw": record,
    }


def normalize_vpc_flow(line: str) -> dict:
    """
    VPC Flow Logs (version 2) fields:
    version account-id interface-id srcaddr dstaddr srcport dstport protocol
    packets bytes start end action log-status
    """
    parts = line.strip().split()
    if len(parts) < 14:
        raise ValueError(f"Unexpected VPC Flow line format: {line!r}")

    return {
        "time": parts[10],  # start epoch (string)
        "source": "vpc_flow",
        "event_type": "vpc_flow",
        "account_id": parts[1],
        "interface_id": parts[2],
        "src_ip": parts[3],
        "dst_ip": parts[4],
        "src_port": parts[5],
        "dst_port": parts[6],
        "protocol": parts[7],
        "packets": parts[8],
        "bytes": parts[9],
        "start": parts[10],
        "end": parts[11],
        "action": parts[12],
        "log_status": parts[13],
        "raw": line.strip(),
    }
