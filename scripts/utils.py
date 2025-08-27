import csv
from pathlib import Path

def load_kev_cve_ids_from_csv(filepath: str | Path) -> set[str]:
    """
    Load CVE IDs from a CISA KEV CSV file.

    Args:
        filepath: Path to the KEV CSV file.

    Returns:
        Set of CVE IDs as uppercase strings.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"KEV CSV file not found: {path}")

    kev_ids: set[str] = set()
    with path.open(newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row.get("cveID") or row.get("CVE")
            if cve_id:
                kev_ids.add(cve_id.strip().upper())
    return kev_ids
