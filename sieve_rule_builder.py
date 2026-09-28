"""Sieve rule builder - turn the hit list into Suricata rules.

Reads sieve-hits.lst (base64 domain per line), decodes it, and writes
DNS / TLS / HTTP detection rules with tracked SIDs into sieve.rules.
SIDs are kept in rule_sids.txt so each run continues where the last left off.
"""

from __future__ import annotations

import base64
import hashlib
import os

HITS_IN = "sieve-hits.lst"
SID_FILE = "rule_sids.txt"
RULES_OUT = "sieve.rules"
MD5_OUT = "sieve.rules.md5"
FIRST_SID = 6000002


def load_last_sid() -> int:
    if os.path.exists(SID_FILE):
        with open(SID_FILE, encoding="utf-8") as fh:
            value = fh.read().strip()
        if value.isdigit():
            return int(value)
    return FIRST_SID


def save_last_sid(sid: int) -> None:
    with open(SID_FILE, "w", encoding="utf-8") as fh:
        fh.write(str(sid))


def decode_hits() -> list:
    if not os.path.exists(HITS_IN):
        return []
    out = []
    with open(HITS_IN, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(base64.b64decode(line).decode().strip())
            except Exception:
                continue
    return out


def build_rules(domains: list, start_sid: int) -> list:
    rules = []
    sid = start_sid
    for domain in domains:
        escaped = domain.replace(".", "\.")
        rules.append(
            f'alert dns any any -> any any (msg:"SIEVE typosquat lookup {domain}"; '
            f'dns.query; content:".{escaped}"; nocase; sid:{sid}; rev:1;)'
        )
        sid += 1
        rules.append(
            f'alert tls any any -> any any (msg:"SIEVE TLS SNI {domain}"; '
            f'tls.sni; content:"{escaped}"; nocase; sid:{sid}; rev:1;)'
        )
        sid += 1
        rules.append(
            f'alert http any any -> any any (msg:"SIEVE http host {domain}"; '
            f'http.host; content:"{escaped}"; nocase; sid:{sid}; rev:1;)'
        )
        sid += 1
    return rules, sid


def run():
    domains = decode_hits()
    if not domains:
        print("[sieve] no hits to convert")
        return
    sid = load_last_sid()
    rules, next_sid = build_rules(domains, sid)
    with open(RULES_OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rules) + "\n")
    save_last_sid(next_sid - 1)
    digest = hashlib.md5(open(RULES_OUT, "rb").read()).hexdigest()
    with open(MD5_OUT, "w", encoding="utf-8") as fh:
        fh.write(digest + "\n")
    print(f"[sieve] wrote {len(rules)} rules (sids {sid}..{next_sid - 1}) to {RULES_OUT}")


if __name__ == "__main__":
    run()
