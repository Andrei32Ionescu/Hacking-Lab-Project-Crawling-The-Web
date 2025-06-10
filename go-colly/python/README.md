# DNS domain resolver checker

The aim of the `dns_checker.py` python script is to check what types of DNS records are present for specified domains.

It takes as input the resulting file (called `input`) from a `title` crawl, finds all domains which were not resolved correctly, checks them against a DNS resolver and outputs the responses in the `dns_results.txt` file. There is a simple sumary at the end of the file as well.

The reason for this script is to investigate whether the domains were not resolved because of a mistake in the crawler (too much concurrency, micconfigured timeouts, ...) or if they have no valid records in the DNS resolver.