import csv
from scripts.process_advisories import parse_advisory

def generate_advisory_csv(input_folder, output_csv, kev_ids=None):
    kev_ids = kev_ids or set()
    fieldnames = [
        "id", "package", "ecosystem", "severity",
        "affected_versions", "patched_versions", "summary",
        "cve_id", "repo", "kev"
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for json_file in input_folder.glob("*.json"):
            try:
                row = parse_advisory(json_file)
                if row["cve_id"] and row["cve_id"] in kev_ids:
                    row["kev"] = "1"
                writer.writerow(row)
            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")