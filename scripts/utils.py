import csv

def load_kev_cve_ids_from_csv(filepath):
    kev_ids = set()
    with open(filepath, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row.get("cveID") or row.get("CVE")
            if cve_id:
                kev_ids.add(cve_id.strip())
    return kev_ids