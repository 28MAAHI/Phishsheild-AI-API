import pytest

from threatintel.normalization.url_normalizer import InvalidURLError, normalize_domain, normalize_url


@pytest.mark.parametrize("raw, expected", [
    ("  HTTP://Example.COM:80/a/./b/../c?x=1#frag  ", "http://example.com/a/c?x=1"),
    ("https://example.com:443", "https://example.com/"),
    ("https://example.com:8443/x", "https://example.com:8443/x"),
    ("http://example.com/%7euser/%2f/%e2%82%ac", "http://example.com/~user/%2F/%E2%82%AC"),
    ("http://example.com/café", "http://example.com/caf%C3%A9"),
    ("hxxp://evil[.]example[.]com/login", "http://evil.example.com/login"),
    ("example.com/path", "http://example.com/path"),
    ("example.com:8080/path", "http://example.com:8080/path"),
    ("http://bücher.example/", None),  # .example is not a public suffix -> rejected below
])
def test_normalization(raw, expected):
    if expected is None:
        with pytest.raises(InvalidURLError):
            normalize_url(raw)
    else:
        assert normalize_url(raw).url == expected


def test_idn_host_is_punycoded():
    n = normalize_url("http://bücher.de/")
    assert n.hostname == "xn--bcher-kva.de"
    assert n.url == "http://xn--bcher-kva.de/"


def test_component_extraction():
    n = normalize_url("https://Login.Secure.Example.co.uk/a/b?q=1")
    assert n.scheme == "https"
    assert n.hostname == "login.secure.example.co.uk"
    assert n.domain == "example.co.uk"
    assert n.registered_domain == "example.co.uk"
    assert n.tld == "co.uk"
    assert n.path == "/a/b"
    assert n.query == "q=1"
    assert not n.is_ip and not n.scheme_assumed


def test_scheme_assumed_flag():
    assert normalize_url("example.com").scheme_assumed is True


def test_public_ip_host_allowed():
    n = normalize_url("http://8.8.8.8/x")
    assert n.is_ip and n.domain is None and n.hostname == "8.8.8.8"


def test_equivalent_spellings_share_hash():
    a = normalize_url("https://LOGIN.example.com:443/verify#top")
    b = normalize_url(" https://login.example.com/./verify ")
    assert a.url == b.url and a.url_hash == b.url_hash
    assert len(a.url_hash) == 64


def test_query_order_preserved():
    assert normalize_url("http://example.com/?b=2&a=1").url == "http://example.com/?b=2&a=1"


@pytest.mark.parametrize("raw, reason", [
    ("", "empty"),
    ("   ", "empty"),
    ("ftp://example.com/file", "unsupported_scheme"),
    ("javascript:alert(1)", "unsupported_scheme"),
    ("http://", "missing_host"),
    ("http://localhost/", "invalid_host"),
    ("http://192.168.1.1/admin", "non_public_ip"),
    ("http://127.0.0.1/", "non_public_ip"),
    ("http://exa mple.com/", "invalid_characters"),
    ("http://example.com/\n", None),  # trailing newline is stripped -> valid
    ("http://foo.notarealtld/", "unknown_tld"),
    ("http://example.com:99999/", "malformed"),
    ("http://-bad-.example.com/", "invalid_host"),
    ("http://example.com/" + "a" * 5000, "too_long"),
])
def test_invalid_urls_rejected(raw, reason):
    if reason is None:
        assert normalize_url(raw).url == "http://example.com/"
        return
    with pytest.raises(InvalidURLError) as e:
        normalize_url(raw)
    assert e.value.reason == reason


def test_non_string_rejected():
    with pytest.raises(InvalidURLError) as e:
        normalize_url(None)  # type: ignore[arg-type]
    assert e.value.reason == "not_a_string"


def test_normalize_domain():
    assert normalize_domain("  Example.COM ") == "example.com"
    for bad in ("", "http://example.com", "a b.com", "localhost"):
        with pytest.raises(InvalidURLError):
            normalize_domain(bad)
