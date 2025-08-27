import json
from pathlib import Path
from zipfile import ZipFile

def parse_advisory(json_path: Path):
    with open(json_path, "r") as f:
        data = json.load(f)

    ghsa_id = data.get("id", "")
    summary = data.get("summary", "")
    severity = data.get("severity", "").capitalize()

    affected = data.get("affected", [{}])[0]
    package = affected.get("package", {}).get("name", "")
    ecosystem = affected.get("package", {}).get("ecosystem", "")
    ranges = affected.get("ranges", [{}])[0].get("events", [])

    introduced = next((e["introduced"] for e in ranges if "introduced" in e), "")
    fixed = next((e["fixed"] for e in ranges if "fixed" in e), "")

    cve_id = next((id["value"] for id in data.get("identifiers", []) if id["type"] == "CVE"), "")
    repo = next((ref["url"].split("github.com/")[1] for ref in data.get("references", []) if "github.com" in ref["url"]), "")

    return {
        "id": ghsa_id,
        "package": package,
        "ecosystem": ecosystem,
        "severity": severity,
        "affected_versions": f"< {fixed}" if fixed else "",
        "patched_versions": fixed,
        "summary": summary,
        "cve_id": cve_id,
        "repo": repo,
        "kev": ""
    }

def zip_advisories_by_severity(advisory_dir: Path, output_dir: Path):
    severity_buckets = {
        "low": [],
        "moderate": [],
        "high": [],
        "critical": []
    }

    for file in advisory_dir.glob("*.json"):
        try:
            data = parse_advisory(file)
            severity = data["severity"].lower()
            if severity in severity_buckets:
                severity_buckets[severity].append(file)
        except Exception as e:
            print(f"Skipping {file.name}: {e}")

    for severity, files in severity_buckets.items():
        if not files:
            continue
        zip_path = output_dir / f"{severity}.zip"
        with ZipFile(zip_path, "w") as zipf:
            for file in files:
                zipf.write(file, arcname=file.name)