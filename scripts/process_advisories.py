import json
from pathlib import Path
from zipfile import ZipFile

def _score_to_bucket(score) -> str:
    try:
        s = float(score)
    except Exception:
        return ""
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Moderate"
    return "Low"

def _extract_severity(data: dict) -> str:
    db = (data.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db:
        return db.strip().capitalize()

    sev = data.get("severity")
    if isinstance(sev, list) and sev:
        for item in sev:
            if isinstance(item, dict) and "score" in item:
                bucket = _score_to_bucket(item.get("score"))
                if bucket:
                    return bucket
        if isinstance(sev[0], str):
            return sev[0].strip().capitalize()

    if isinstance(sev, str) and sev:
        return sev.strip().capitalize()

    return ""

def parse_advisory(json_path: Path) -> dict:
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    ghsa_id = data.get("id", "") or ""
    summary = data.get("summary", "") or ""
    severity = _extract_severity(data)

    affected_list = data.get("affected") or []
    first_aff = affected_list[0] if affected_list else {}
    pkg = (first_aff.get("package") or {})
    package = pkg.get("name", "") or ""
    ecosystem = pkg.get("ecosystem", "") or ""

    ranges = (first_aff.get("ranges") or [])
    events = (ranges[0].get("events") if ranges else []) or []
    fixed = next((e.get("fixed") for e in events if "fixed" in e), "")
    affected_versions = f"< {fixed}" if fixed else ""

    cve_id = next(
        (i.get("value") for i in (data.get("identifiers") or []) if i.get("type") == "CVE"),
        "",
    ) or ""

    repo = ""
    for ref in (data.get("references") or []):
        url = ref.get("url", "")
        if "github.com/" in url:
            repo = url
            break

    return {
        "id": ghsa_id,
        "package": package,
        "ecosystem": ecosystem,
        "severity": severity,
        "affected_versions": affected_versions,
        "patched_versions": fixed or "",
        "summary": summary,
        "cve_id": cve_id,
        "repo": repo,
        "kev": "",
    }

def _iter_json_files(root: Path):
    yield from root.glob("*.json")
    yield from root.glob("**/*.json")

def zip_advisories_by_severity(advisory_dir: Path, output_dir: Path) -> None:
    buckets: dict[str, list[Path]] = {"low": [], "moderate": [], "high": [], "critical": []}

    for file in _iter_json_files(advisory_dir):
        try:
            row = parse_advisory(file)
            sev = (row.get("severity") or "").lower()
            if sev in buckets:
                buckets[sev].append(file)
        except Exception as e:
            print(f"Skipping {file.name}: {e}")

    output_dir.mkdir(parents=True, exist_ok=True)
    for sev, files in buckets.items():
        if not files:
            continue
        zip_path = output_dir / f"{sev}.zip"
        with ZipFile(zip_path, "w") as zipf:
            for file in files:
                zipf.write(file, arcname=file.name)
