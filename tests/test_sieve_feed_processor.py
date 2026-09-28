from sieve_feed_processor import split_domain, looks_phishy


def test_split_domain_plain():
    assert split_domain("login.paypal.com") == ("paypal.com", "paypal")


def test_split_domain_lowercases():
    assert split_domain("  CHASE.COM ") == ("chase.com", "chase")


def test_split_domain_without_tld():
    assert split_domain("localhost") == ("localhost", "localhost")


def test_permutation_hit():
    assert looks_phishy("paypa1.com", {"paypa1.com"}) is True


def test_brand_plus_bait_word():
    assert looks_phishy("paypal-login-verify.com", set()) is True


def test_benign_domain():
    assert looks_phishy("example.com", set()) is False
