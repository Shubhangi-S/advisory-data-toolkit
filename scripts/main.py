import argparse
from pathlib import Path
from scripts.download_advisories import download_advisories
from scripts.process_advisories import zip_advisories_by_severity
from scripts.generate_csv import generate_advisory_csv
from scripts.utils import load_kev_cve_ids_from_csv

def main(advisory_dir, output_dir, kev_path=None):
    advisory_path = Path(advisory_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    kev_ids = set()
    if kev_path:
        kev_ids = load_kev_cve_ids_from_csv(Path(kev_path))

    csv_output = output_path / "github_advisories.csv"
    generate_advisory_csv(advisory_path, csv_output, kev_ids)

    zipped_dir = output_path / "zipped_advisories"
    zipped_dir.mkdir(exist_ok=True)
    zip_advisories_by_severity(advisory_path, zipped_dir)

    print(f"✅ CSV generated: {csv_output}")
    print(f"✅ Zipped advisories saved to: {zipped_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process GitHub Advisories")
    parser.add_argument("--advisories", required=True, help="Path to folder with advisory .json files")
    parser.add_argument("--output", required=True, help="Folder to save outputs (CSV + ZIPs)")
    parser.add_argument("--kev", required=False, help="Path to local cisa_kev.csv file")
    args = parser.parse_args()
    main(args.advisories, args.output, args.kev)