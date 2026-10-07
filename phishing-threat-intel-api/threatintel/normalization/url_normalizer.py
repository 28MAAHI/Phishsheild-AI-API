"""URL validation and normalisation.

Every URL is normalised before storage so that trivially different spellings
of the same address map to one database row:

  * surrounding whitespace removed; embedded whitespace/control chars rejected
  * defanged notation (hxxp://, [.]) restored
  * scheme and host lower-cased; host converted to IDNA (punycode) ASCII
  * default ports (:80 for http, :443 for https) removed
  * percent-encoding normalised (RFC 3986 §6.2.2): hex digits upper-cased,
    encoded unreserved characters decoded, non-ASCII characters encoded
  * dot segments (/./, /../) resolved; empty path becomes "/"
  * fragment (#...) dropped: browsers never send it to the server
  * query parameter order is preserved (it can be meaningful)

The path and query keep their case: servers may treat them case-sensitively.

Validation rejects anything that is not an http(s) URL with a public host:
other schemes, missing/invalid host names, unknown top-level domains,
non-public IP addresses (private, loopback, link-local, ...), bad ports and
over-long input. Rejections carry a machine-readable reason code.

Domain splitting uses tldextract's bundled Public Suffix List snapshot and
never makes network calls.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

DEFAULT_MAX_LENGTH = 4096

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_EXTRACT_ICANN = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_PCT_RE = re.compile(r"%([0-9a-fA-F]{2})")
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# Characters allowed literally in a path/query (RFC 3986 pchar + "/" + "?").
_ALLOWED = _UNRESERVED | set("!$&'()*+,;=:@/?%")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidURLError(ValueError):
    """Raised for input that cannot be stored as a URL. `reason` is a stable code."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class NormalizedURL:
    url: str                 # canonical form stored in the database
    url_hash: str            # sha256 hex of `url`; the uniqueness key
    scheme: str
    hostname: str            # ASCII/IDNA form, lower-case
    domain: str | None       # registrable domain (PSL incl. private suffixes); None for IPs
    registered_domain: str | None  # registrable domain under ICANN suffixes only
    tld: str | None          # public suffix, e.g. "com", "co.uk"
    port: int | None         # only non-default ports
    path: str
    query: str | None
    is_ip: bool
    scheme_assumed: bool     # input had no scheme; http:// was assumed


def _normalize_pct(component: str) -> str:
    """Normalise percent-encoding in a path or query component."""
    def _fix(m: re.Match) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()

    out = []
    for ch in _PCT_RE.sub(_fix, component):
        if ch in _ALLOWED:
            out.append(ch)
        else:  # non-ASCII or otherwise disallowed characters -> UTF-8 percent-encoding
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8")))
    # A lone '%' not followed by two hex digits is invalid; encode it.
    return re.sub(r"%(?![0-9A-F]{2})", "%25", "".join(out))


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4."""
    if "." not in path:
        return path
    segments = path.split("/")
    out: list[str] = []
    for seg in segments[1:] if path.startswith("/") else segments:
        if seg == "..":
            if out:
                out.pop()
        elif seg != ".":
            out.append(seg)
    result = "/" + "/".join(out)
    if segments[-1] in (".", ".."):
        result += "/" if not result.endswith("/") else ""
    return result


def _parse_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _normalize_host(host: str) -> tuple[str, bool]:
    """Return (ascii_host, is_ip). Raises InvalidURLError."""
    host = host.strip().rstrip(".").lower()
    if not host:
        raise InvalidURLError("missing_host", "URL has no host name.")

    ip = _parse_ip(host)
    if ip is not None:
        if not ip.is_global:
            raise InvalidURLError("non_public_ip", f"IP address {host} is not publicly routable.")
        return (ip.compressed if ip.version == 4 else ip.compressed), True

    try:
        ascii_host = host.encode("idna").decode("ascii") if any(ord(c) > 127 for c in host) else host
    except UnicodeError:
        raise InvalidURLError("invalid_host", f"Host name '{host}' is not a valid internationalised domain.") from None

    if len(ascii_host) > 253:
        raise InvalidURLError("invalid_host", "Host name is longer than 253 characters.")
    labels = ascii_host.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(lbl) for lbl in labels):
        raise InvalidURLError("invalid_host", f"'{ascii_host}' is not a valid domain name.")
    return ascii_host, False


def normalize_url(raw: str, max_length: int = DEFAULT_MAX_LENGTH) -> NormalizedURL:
    """Validate and normalise one URL. Raises InvalidURLError."""
    if not isinstance(raw, str):
        raise InvalidURLError("not_a_string", "URL must be a string.")
    url = raw.strip()
    if not url:
        raise InvalidURLError("empty", "URL is empty.")
    if len(url) > max_length:
        raise InvalidURLError("too_long", f"URL exceeds {max_length} characters.")
    if _CONTROL_OR_SPACE_RE.search(url):
        raise InvalidURLError("invalid_characters", "URL contains whitespace or control characters.")

    # Restore defanged notation used in threat reports.
    url = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)
    url = url.replace("[.]", ".").replace("[:]", ":")

    scheme_assumed = False
    m = _SCHEME_RE.match(url)
    if not m or not url[m.end():].startswith("//"):
        if m and m.group(1).lower() not in ("http", "https") and not url[m.end():m.end() + 1].isdigit():
            raise InvalidURLError("unsupported_scheme", f"Scheme '{m.group(1).lower()}' is not supported.")
        url = "http://" + url
        scheme_assumed = True

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise InvalidURLError("malformed", f"URL could not be parsed: {e}") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURLError("unsupported_scheme", f"Scheme '{scheme}' is not supported.")
    if parts.hostname is None:
        raise InvalidURLError("missing_host", "URL has no host name.")

    hostname, is_ip = _normalize_host(parts.hostname)

    domain = registered = tld = None
    if not is_ip:
        ext = _EXTRACT(hostname)
        if not ext.suffix or not ext.domain:
            raise InvalidURLError("unknown_tld", f"'{hostname}' does not end in a known public suffix.")
        domain = f"{ext.domain}.{ext.suffix}"
        tld = ext.suffix
        icann = _EXTRACT_ICANN(hostname)
        registered = f"{icann.domain}.{icann.suffix}" if icann.domain and icann.suffix else domain

    if port is not None and port == _DEFAULT_PORTS[scheme]:
        port = None

    userinfo = ""
    if "@" in parts.netloc:
        userinfo = _normalize_pct(parts.netloc.rsplit("@", 1)[0]) + "@"

    host_for_url = f"[{hostname}]" if is_ip and ":" in hostname else hostname
    netloc = f"{userinfo}{host_for_url}" + (f":{port}" if port is not None else "")

    path = _remove_dot_segments(_normalize_pct(parts.path)) or "/"
    query = _normalize_pct(parts.query) if parts.query else None

    canonical = f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")
    if len(canonical) > max_length:
        raise InvalidURLError("too_long", f"Normalised URL exceeds {max_length} characters.")

    return NormalizedURL(
        url=canonical,
        url_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        scheme=scheme, hostname=hostname, domain=domain, registered_domain=registered, tld=tld,
        port=port, path=path, query=query, is_ip=is_ip, scheme_assumed=scheme_assumed,
    )


def normalize_domain(raw: str) -> str:
    """Normalise a bare domain/host name supplied as a query parameter."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidURLError("empty", "Domain is empty.")
    value = raw.strip().lower()
    if "/" in value or "@" in value or _CONTROL_OR_SPACE_RE.search(value):
        raise InvalidURLError("invalid_host", "Supply a domain or host name only, not a URL.")
    host, _ = _normalize_host(value)
    return host
