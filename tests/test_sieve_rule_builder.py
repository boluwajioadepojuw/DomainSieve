import base64
import os

from sieve_rule_builder import build_rules, decode_hits, load_last_sid, save_last_sid


def test_sid_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_last_sid() == 6000002


def test_sid_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    save_last_sid(6000100)
    assert load_last_sid() == 6000100


def test_decode_hits(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with open("sieve-hits.lst", "w", encoding="utf-8") as fh:
        fh.write(base64.b64encode(b"paypa1.com").decode() + "\n")
    assert decode_hits() == ["paypa1.com"]


def test_build_rules_counts():
    rules, next_sid = build_rules(["paypa1.com"], 6000002)
    assert len(rules) == 3
    assert next_sid == 6000005
    assert "SIEVE" in rules[0]
