# DomainSieve

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-frequency dynamic signature ruleset for mitigating phishing attacks.
Automated pipeline ingests community threat feeds, performs structural analysis
of newly registered domains, and generates Suricata detection rules for DNS, TLS,
and HTTP layers.

Features:
- Newly Registered Domain (NRD) monitoring pipeline
- dnstwist typosquatting and homoglyph detection
- Automated Suricata rule generation (SIDs 6000000-6100000)
- PhishStats and OpenPhish feed ingestion
- Traceability: suspicious domains archived for auditing
- Deployment guides for GNU/Linux and pfSense

Stack: Python, Suricata, dnstwist

## Author

Boluwaji Oluwaseyi Adepoju
