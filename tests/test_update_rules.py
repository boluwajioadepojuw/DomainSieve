import base64

import pytest

import update_rules


def test_get_last_sid_defaults_to_first_http_sid(tmp_path, monkeypatch):
    monkeypatch.setattr(update_rules, "sid_file", str(tmp_path / "sid_tracker.txt"))
    assert update_rules.get_last_sid() == 6000002


def test_get_last_sid_reads_existing_value(tmp_path, monkeypatch):
    sid_path = tmp_path / "sid_tracker.txt"
    sid_path.write_text("6000100")
    monkeypatch.setattr(update_rules, "sid_file", str(sid_path))
    assert update_rules.get_last_sid() == 6000100


def test_is_domain_in_rules_true():
    rules = ['alert http any any -> any any (msg:"x"; http.host; content:"evil.com"; endswith; sid:1;)' ]
    assert update_rules.is_domain_in_rules("evil.com", rules) is True


def test_is_domain_in_rules_false():
    assert update_rules.is_domain_in_rules("evil.com", []) is False


def test_is_domain_in_phishing_list_true(tmp_path, monkeypatch):
    list_path = tmp_path / "phishing.lst"
    encoded = base64.b64encode(b"evil.com").decode()
    list_path.write_text(encoded + "\n")
    monkeypatch.setattr(update_rules, "phishing_list", str(list_path))
    assert update_rules.is_domain_in_phishing_list("evil.com") is True


def test_is_domain_in_phishing_list_false(tmp_path, monkeypatch):
    monkeypatch.setattr(update_rules, "phishing_list", str(tmp_path / "missing.lst"))
    assert update_rules.is_domain_in_phishing_list("evil.com") is False


def test_create_rules_generates_http_rule_for_url_with_path():
    rules, new_sid = update_rules.create_suricata_rules(
        ["http://bad.com/login.php"], "phishstats.info", 6000002, []
    )
    assert new_sid == 6000003
    assert len(rules) == 1
    rule = rules[0]
    assert 'content:"bad.com"' in rule
    assert 'content:"/login.php"' in rule
    assert "sid:6000002;" in rule
    assert 'reference:url,phishstats.info' in rule


def test_create_rules_escapes_quote_in_path():
    rules, _ = update_rules.create_suricata_rules(
        ['http://evil.com/a"b'], "openphish.com", 6000002, []
    )
    assert "|22|" in rules[0]
    assert 'content:"/a|22|b"' in rules[0]


def test_create_rules_dedupes_duplicate_urls():
    rules, new_sid = update_rules.create_suricata_rules(
        ["http://x.com/a", "http://x.com/a"], "openphish.com", 6000002, []
    )
    assert len(rules) == 1
    assert new_sid == 6000003


def test_create_rules_skips_domain_already_in_rules():
    existing = ['alert http any any -> any any (msg:"x"; http.host; content:"evil.com"; endswith; sid:1;)' ]
    rules, new_sid = update_rules.create_suricata_rules(
        ["http://evil.com/again"], "phishstats.info", 6000002, existing
    )
    assert rules == []
    assert new_sid == 6000002


def test_create_rules_adds_domain_only_entry_to_phishing_list(tmp_path, monkeypatch):
    list_path = tmp_path / "phishing.lst"
    list_path.write_text("")
    monkeypatch.setattr(update_rules, "phishing_list", str(list_path))
    rules, new_sid = update_rules.create_suricata_rules(
        ["plain-domain.com"], "phishstats.info", 6000002, []
    )
    assert rules == []
    encoded = base64.b64encode(b"plain-domain.com").decode()
    assert encoded in list_path.read_text()


def test_create_rules_sids_increase_without_collisions():
    rules, new_sid = update_rules.create_suricata_rules(
        ["http://a.com/1", "http://b.com/2", "http://c.com/3"], "openphish.com", 6000002, []
    )
    assert len(rules) == 3
    assert new_sid == 6000005
    sids = [line.split("sid:", 1)[1].split(";", 1)[0] for line in rules]
    assert sids == ["6000002", "6000003", "6000004"]
