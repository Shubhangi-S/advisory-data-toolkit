import json
from pathlib import Path
from scripts.process_advisories import parse_advisory


def test_parse_advisory_with_moderate_severity(tmp_path: Path):
    """Basic sanity check: ensure severity parsing works."""

    sample = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Test advisory",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"name": "demo", "ecosystem": "PIP"},
                "ranges": [],
            }
        ],
        "identifiers": [{"type": "CVE", "value": "CVE-2025-0001"}],
        "references": [{"url": "https://github.com/example/repo"}],
    }

    # Write temporary JSON file
    file_path = tmp_path / "advisory.json"
    file_path.write_text(json.dumps(sample))

    # Parse it
    row = parse_advisory(file_path)

    # Assertions
    assert row["id"] == "GHSA-xxxx-yyyy-zzzz"
    assert row["package"] == "demo"
    assert row["ecosystem"] == "PIP"
    assert row["severity"] == "Moderate"  # normalized
    assert row["cve_id"] == "CVE-2025-0001"
    assert row["repo"] == "https://github.com/example/repo"
