# DomainSieve

A dynamic signature ruleset for catching phishing domains before they get
used. An automated pipeline pulls community threat feeds, checks newly
registered domains for structure problems, and turns the findings into
Suricata detection rules for DNS, TLS, and HTTP.

What it covers:

- Newly Registered Domain (NRD) monitoring pipeline
- dnstwist typosquatting and homoglyph detection
- Automated Suricata rule generation (SIDs 6000000-6100000)
- PhishStats and OpenPhish feed ingestion
- Traceability: suspicious domains archived for auditing
- Deployment guides for GNU/Linux and pfSense

Stack: Python, Suricata, dnstwist

## Author

Boluwaji Oluwaseyi Adepoju
