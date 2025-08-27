import csv
import sys
from pathlib import Path
from typing import Iterable, Set, Tuple

from scripts.process_advisories import parse_advisory

def _iter_json_files(root: Path) -> Iterable[Path]:
    yield from root.glob("*.json")
    yield from root.glob("**/*.json")

def generate_advisory_csv(
    input_folder: Path | str,
    output_csv: Path | str,
    kev_ids: Set[str] | None = None,
) -> Tuple[int, int]:
    """
    Generate a CSV from advisory JSON files.

    Returns:
        (num_written, num_errors)
    """
    kev = {k.strip().upper() for k in (kev_ids or set()) if k}

    in_dir = Path(input_folder)
    out_path = Path(output_csv)
    if not in_dir.exists() or not in_dir.is_dir():
        raise FileNotFoundError(f"Input folder does not exist or is not a directory: {in_dir}")

    fieldnames = [
        "id",
        "package",
        "ecosystem",
        "severity",
        "affected_versions",
        "patched_versions",
        "summary",
        "cve_id",
        "repo",
        "kev",
    ]

    num_written = 0
    num_errors = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for json_file in _iter_json_files(in_dir):
            try:
                row = parse_advisory(json_file)
                cve = (row.get("cve_id") or "").strip().upper()
                row["kev"] = "1" if cve and cve in kev else ""
                writer.writerow(row)
                num_written += 1
            except Exception as e:
                print(f"Error processing {json_file}: {e}", file=sys.stderr)
                num_errors += 1

    return num_written, num_errors
