"""Sieve feed processor - pull the daily NRD list and keep what looks phishy.

Pipeline: download the Newly Registered Domains feed, build a permutation
set of the brands worth protecting, then keep domains that either match a
permutation or carry a brand name plus a bait keyword. Output is two files:

- sieve-nrd-domains.txt : plaintext suspicious domains
- sieve-hits.lst        : base64 lines, ready for the rule builder
"""

from __future__ import annotations

import os
import re
from base64 import b64encode

import dnstwist
import requests
import tldextract

FEED_URL = "https://raw.githubusercontent.com/cbuijs/nrd/main/nrd-1d.domains.list"
NRD_OUT = "sieve-nrd-domains.txt"
HITS_OUT = "sieve-hits.lst"

WATCH_BRANDS = [
    "chase.com", "paypal.com", "revolut.com", "wise.com", "santander.com",
    "amazon.com", "ebay.com", "stripe.com", "apple.com", "microsoft.com",
    "google.com", "netflix.com", "dropbox.com", "binance.com", "coinbase.com",
    "metamask.io", "ledger.com", "telegram.org", "discord.com", "linkedin.com",
]

BRAND_NAMES = [b.split(".")[0] for b in WATCH_BRANDS]

BAIT_WORDS = [
    "login", "signin", "verify", "account", "secure", "update", "support",
    "billing", "auth", "portal", "alert", "restore", "bank", "wallet",
]


def split_domain(domain: str):
    clean = domain.lower().strip()
    parts = tldextract.extract(clean)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}", parts.domain
    return clean, clean.split(".")[0]


def build_permutations():
    found = set()
    for brand in WATCH_BRANDS:
        try:
            fuzzer = dnstwist.Fuzzer(brand)
            fuzzer.generate()
            for entry in fuzzer.domains:
                name = entry.get("domain") if isinstance(entry, dict) else str(entry)
                if name:
                    found.add(name.lower())
        except Exception:
            continue
    return found


def pull_feed():
    try:
        resp = requests.get(FEED_URL, timeout=30)
        if resp.status_code != 200:
            return []
        return list(dict.fromkeys(l.strip().lower() for l in resp.text.splitlines() if l.strip()))
    except Exception:
        return []


def looks_phishy(domain: str, permutations: set) -> bool:
    registered, brand_part = split_domain(domain)
    if registered in permutations or domain in permutations:
        return True
    for brand in BRAND_NAMES:
        if brand not in brand_part:
            continue
        for word in BAIT_WORDS:
            if word in brand_part:
                return True
        if re.search(rf"{brand}[\d-]|[\d-]{brand}", brand_part):
            return True
        deobf = brand_part.replace("0", "o").replace("1", "l").replace("3", "e")
        if brand in deobf:
            return True
    return False


def run():
    domains = pull_feed()
    if not domains:
        print("[sieve] feed empty, nothing to do")
        return
    perms = build_permutations()
    hits = [d for d in domains if looks_phishy(d, perms)]
    with open(NRD_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hits) + "\n")
    with open(HITS_OUT, "w", encoding="utf-8") as fh:
        for d in hits:
            fh.write(b64encode(d.encode()).decode() + "\n")
    print(f"[sieve] {len(hits)} suspicious domains out of {len(domains)} checked")


if __name__ == "__main__":
    run()
