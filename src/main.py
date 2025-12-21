import json
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

    out_path = OUTPUT_DIR / "events.jsonl"
    write_jsonl(out_path, events)

    print(f"Wrote {len(events)} events to {out_path}")


if __name__ == "__main__":
    main()

