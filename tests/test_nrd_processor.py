import os

import pytest

from nrd_processor import extract_registered_domain, evaluate_nrd_domain


def test_extract_registered_domain_plain():
    assert extract_registered_domain("login.paypal.com") == ("paypal.com", "paypal")


def test_extract_registered_domain_lowercases_and_trims():
    assert extract_registered_domain("  CHASE.COM ") == ("chase.com", "chase")


def test_extract_registered_domain_without_tld():
    # tldextract has nothing to split here, so the domain passes through as-is
    assert extract_registered_domain("localhost") == ("localhost", "localhost")


def test_evaluate_flags_domain_in_permutation_set():
    perms = {"paypa1.com"}
    assert evaluate_nrd_domain("paypa1.com", perms) is True


def test_evaluate_flags_brand_plus_keyword():
    assert evaluate_nrd_domain("paypal-login.com", set()) is True


def test_evaluate_flags_brand_with_digits():
    assert evaluate_nrd_domain("chase123.com", set()) is True


def test_evaluate_flags_leetspeak_brand():
    # "paypa1" normalizes to "paypal", which is not literally in the domain
    assert evaluate_nrd_domain("paypa1.com", set()) is True


def test_evaluate_ignores_clean_domain():
    assert evaluate_nrd_domain("example.com", set()) is False


def test_evaluate_does_not_flag_legit_brand_domain():
    # the real brand domain has no keyword or digit pattern attached
    assert evaluate_nrd_domain("paypal.com", set()) is False
