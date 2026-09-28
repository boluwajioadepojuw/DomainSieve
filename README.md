# DomainSieve

A phishing-domain sieve for a small SOC: every day it downloads the Newly
Registered Domains feed, keeps the domains that look like brand
impersonation, and turns them into Suricata rules the gateway can load.

## How it works

1. sieve_feed_processor.py downloads the daily NRD list and builds a
dnstwist permutation set of the watched brands (banks, crypto, big
consumer brands).
2. A domain is kept when it matches a permutation, or when it carries a
brand name plus a bait word (login, verify, billing, support...), or
when its leetspeak form decodes to a brand.
3. sieve_rule_builder.py reads the hit list and writes DNS / TLS / HTTP
Suricata rules with tracked SIDs (6000002 and up) into sieve.rules,
plus an md5 for the distribution pipeline.

Output files: sieve-nrd-domains.txt (plain), sieve-hits.lst (base64),
sieve.rules + sieve.rules.md5 (for the gateway).

## Why this shape

One feed, one pass, three rule types. No dashboard, no API, no state
beyond the SID file - everything an L1 analyst can read in ten minutes
and everything a pfSense or OPNsense box can consume directly.

## Running it

```bash
pip install -r requirements.txt
python3 sieve_feed_processor.py      # fetch + classify
python3 sieve_rule_builder.py        # emit Suricata rules
./check-rule-url.sh                  # verify one rule URL, optional
```

See docs/sample-run.txt for a real run against the feed.

## Author

Boluwaji Oluwaseyi Adepoju
