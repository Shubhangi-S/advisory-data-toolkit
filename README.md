# Advisory Data Toolkit

This project processes security advisories into structured outputs. It ingests JSON advisories (from the GitHub Advisory Database), normalizes fields, groups by severity, and produces both CSV summaries and zipped advisories. Optionally, it enriches results with the CISA Known Exploited Vulnerabilities (KEV) catalog.

---

## Approach and Reasoning
- **Parsing JSON at scale**: GitHub advisories are nested and inconsistent, so I wrote a parser that handles multiple severity formats (`database_specific.severity`, CVSS scores, or string lists).  
- **Outputs**: I decided to generate two things:
  1. A CSV with consistent fields: id, package, ecosystem, severity, versions, summary, CVE, repo reference, and a KEV flag.  
  2. ZIPs of advisories grouped into low, moderate, high, and critical.  
- **KEV integration**: CISA’s KEV catalog is a practical way to flag vulnerabilities that are actually exploited.  
- **Performance/scalability**: Designed to work with the full GitHub advisory-database (~hundreds of thousands of JSON files).  
- **Repo design**: Kept `data/` and `output/` out of version control to keep it lightweight. Added `tests/` with a minimal unit test for severity parsing.

---

## Setup
1. Clone this repository.  
2. Use Python 3.10+ (or adjust type hints for 3.9).  
3. Place advisory JSON files into `data/raw_advisories/`.  
4. (Optional) Download CISA’s KEV CSV file into the repo root:  
   https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv  

No external dependencies — everything runs on the Python standard library.

---

## Usage
From the project root:

```bash
# Without KEV enrichment
python -m scripts.main --advisories data/raw_advisories --output output

# With KEV enrichment
python -m scripts.main --advisories data/raw_advisories --output output --kev cisa_kev.csv
```

---

## Outputs

- `output/github_advisories.csv` → tabular summary of advisories.  
- `output/zipped_advisories/` → low.zip, moderate.zip, high.zip, critical.zip.  

Each CSV row includes:  
`id, package, ecosystem, severity, affected_versions, patched_versions, summary, cve_id, repo, kev`

---

## Notes

- Data and outputs are not stored in the repo — they’re generated when you run the scripts.  
- The tests/ directory includes a minimal unit test (test_process.py) that validates severity parsing. With more time, this could be extended to CSV generation and KEV matching.
- Running on the full advisory-database produces warnings from Python’s `zipfile` about duplicate filenames (when the same GHSA ID exists in multiple subfolders). These don’t affect the CSV or the contents of the ZIPs.  

---

## Example Run

- Processed ~16,000 advisories.  
- Zero parse errors.  
- CSV and all severity ZIPs generated correctly.  
- KEV enrichment works — CVEs present in the KEV catalog are flagged with `kev=1`.  

---

## License

MIT or Apache-2.0
