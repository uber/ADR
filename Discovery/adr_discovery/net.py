"""Hostname handling shared by the probes.

Substring matching on hosts is wrong in both directions: ``evilcorp.example``
ends with ``corp.example`` and is not part of it, and ``api.openai.com.evil.test``
contains ``api.openai.com`` and is not it. Both mistakes turn a tenant's
allow-list into an attacker's convenience.
"""

from typing import Optional
from urllib.parse import urlsplit


def host_of(target: str) -> Optional[str]:
    """Extract the hostname from a URL or a browser permission pattern.

    Delegated to a URL parser rather than split on the first colon, because a
    bracketed IPv6 authority has colons inside it: hand-splitting turns
    ``http://[::1]:8000/v1`` into ``[`` and quietly breaks every policy decision
    that depends on the host.
    """
    text = str(target or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "//" + text
    try:
        parts = urlsplit(text if "://" in text else "http:" + text)
        host = parts.hostname
    except ValueError:
        host = None
    if not host:
        # A wildcard authority is not a valid URL host; take it literally.
        host = text.split("://", 1)[-1].split("/", 1)[0]
    host = host.lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    return host or None


def domain_matches(host: Optional[str], domain: str) -> bool:
    """True when ``host`` is ``domain`` or a subdomain of it, never a suffix of it."""
    if not host or not domain:
        return False
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def matches_any(host: Optional[str], domains) -> bool:
    return any(domain_matches(host, domain) for domain in domains or ())
