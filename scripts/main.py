import argparse
import sys
from pathlib import Path

from scripts.download_advisories import download_advisories  # stub
from scripts.process_advisories import zip_advisories_by_severity
from scripts.generate_csv import generate_advisory_csv
from scripts.utils import load_kev_cve_ids_from_csv

def main(advisory_dir: str, output_dir: str, kev_path: str | None = None) -> int:
    in_dir = Path(advisory_dir)
    out_dir = Path(output_dir)

    if not in_dir.exists() or not in_dir.is_dir():
        print(f"[error] Input folder does not exist or is not a directory: {in_dir}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    kev_ids = set()
    if kev_path:
        kev_file = Path(kev_path)
        if not kev_file.exists():
            print(f"[warn] KEV file not found: {kev_file}. Continuing without KEV.", file=sys.stderr)
        else:
            kev_ids = load_kev_cve_ids_from_csv(kev_file)

    csv_output = out_dir / "github_advisories.csv"
    written, errors = generate_advisory_csv(in_dir, csv_output, kev_ids)

    zipped_dir = out_dir / "zipped_advisories"
    zipped_dir.mkdir(exist_ok=True)
    zip_advisories_by_severity(in_dir, zipped_dir)

    print(f"CSV:   {csv_output}")
    print(f"Rows:  {written}   Errors: {errors}")
    print(f"ZIPs:  {zipped_dir}")

    return 0 if written > 0 else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process GitHub Advisories")
    parser.add_argument("--advisories", required=True, help="Folder containing advisory .json files")
    parser.add_argument("--output", required=True, help="Folder to save outputs (CSV + ZIPs)")
    parser.add_argument("--kev", required=False, help="Path to local cisa_kev.csv file")
    args = parser.parse_args()
    sys.exit(main(args.advisories, args.output, args.kev))
