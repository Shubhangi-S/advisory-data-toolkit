# Advisory Data Toolkit

This tool downloads and processes GitHub security advisories. It groups advisories by severity into ZIP files and creates a CSV summary. Optionally, it cross-checks against the CISA Known Exploited Vulnerabilities (KEV) catalog.

## Usage

```bash
python scripts/main.py --advisories data/raw_advisories --output output --kev cisa_kev.json
```

### Arguments

- `--advisories`: Folder containing advisory `.json` files (cloned or downloaded from GitHub Advisory DB)
- `--output`: Output folder to save `CSV` and `ZIP` files
- `--kev`: *(Optional)* Path to `cisa_kev.json` for KEV cross-check

## Output

- `github_advisories.csv`: Summary of all advisories
- `zipped_advisories/*.zip`: Zips by severity (`low.zip`, `moderate.zip`, etc)

## Skills Demonstrated

- JSON parsing, severity classification
- File I/O, CSV generation
- CVE enrichment via external catalog
- CLI packaging and automation

---
MIT License.
