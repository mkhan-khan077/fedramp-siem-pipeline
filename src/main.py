import json
from src.enrich import enrich
from src.detections import detect
from pathlib import Path
from typing import List, Dict

from src.normalize import normalize_cloudtrail, normalize_vpc_flow, normalize_windows

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def write_jsonl(path: Path, records: List[Dict]) -> None:
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def main() -> None:
    events: List[Dict] = []

    # CloudTrail (JSON)
    with open("sample_logs/cloudtrail.json") as f:
        record = json.load(f)
        events.append(normalize_cloudtrail(record))

    # Windows event (JSON)
    with open("sample_logs/windows_event.json") as f:
        record = json.load(f)
        events.append(normalize_windows(record))

    # VPC Flow (text lines)
    with open("sample_logs/vpc_flow.log") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(normalize_vpc_flow(line))

    enriched_events = [enrich(e) for e in events]

    alerts = []
    for e in enriched_events:
    	alerts.extend(detect(e))
 
    write_jsonl(OUTPUT_DIR / "events.jsonl", enriched_events)
    write_jsonl(OUTPUT_DIR / "alerts.jsonl", alerts)

    print(f"Wrote {len(enriched_events)} events to outputs/events.jsonl")
    print(f"Wrote {len(alerts)} alerts to outputs/alerts.jsonl")


if __name__ == "__main__":
    main()

