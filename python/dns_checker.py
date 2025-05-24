import re
import dns.resolver
from collections import defaultdict

INPUT_FILE = "input.log"
OUTPUT_FILE = "dns_results.txt"

DNS_ERROR_PATTERN = re.compile(r"dial tcp: lookup ([^:]+): no such host")

def extract_failed_domains(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        content = file.read()
    return sorted(set(DNS_ERROR_PATTERN.findall(content)))

def resolve_domain(domain):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answers.rrset:
                results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
    return results

def main():
    failed_domains = extract_failed_domains(INPUT_FILE)[1:]
    total = len(failed_domains)

    # Counters
    domains_with_records = 0
    domains_with_no_records = 0
    record_type_counts = defaultdict(int)  # counts of domains per record type

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write(f"Checked {total} domains with DNS lookup errors\n\n")

        for idx, domain in enumerate(failed_domains, 1):
            out.write(f"{idx}. Domain: {domain}\n")
            records = resolve_domain(domain)
            if records:
                domains_with_records += 1
                # Count record types for this domain
                for rtype in records.keys():
                    record_type_counts[rtype] += 1

                out.write("   ✅ DNS records found:\n")
                for rtype, values in records.items():
                    out.write(f"   - {rtype}:\n")
                    for val in values:
                        out.write(f"     • {val}\n")
            else:
                domains_with_no_records += 1
                out.write("   ❌ No DNS records found.\n")
            out.write("-" * 60 + "\n")

        # Summary
        out.write("\n" + "="*60 + "\n")
        out.write("Summary:\n")
        out.write(f"Total domains checked        : {total}\n")
        out.write(f"Domains with DNS records     : {domains_with_records}\n")
        out.write(f"Domains with NO DNS records  : {domains_with_no_records}\n\n")
        
        out.write("Domains with each record type:\n")
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']:
            count = record_type_counts.get(rtype, 0)
            out.write(f"  - {rtype}: {count}\n")
        out.write("="*60 + "\n")

if __name__ == "__main__":
    main()
