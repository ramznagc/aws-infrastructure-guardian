import json
from pathlib import Path


def write_json_report(data, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as report_file:
        json.dump(data, report_file, indent=2)

    return path