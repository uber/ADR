"""Hostname handling shared by the probes.

Substring matching on hosts is wrong in both directions: ``evilcorp.example``
ends with ``corp.example`` and is not part of it, and ``api.openai.com.evil.test``
contains ``api.openai.com`` and is not it. Both mistakes turn a tenant's
allow-list into an attacker's convenience.
"""

from typing import Optional


def host_of(target: str) -> Optional[str]:
    """Extract the hostname from a URL or a browser permission pattern."""
    text = str(target or "").strip()
    if not text:
        return None
    if "://" in text:
        text = text.split("://", 1)[1]
    else:
        text = text.lstrip("*.")
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:
        text = text.split("@", 1)[1]
    text = text.split(":", 1)[0]
    return text.lower().strip(".") or None


def domain_matches(host: Optional[str], domain: str) -> bool:
    """True when ``host`` is ``domain`` or a subdomain of it, never a suffix of it."""
    if not host or not domain:
        return False
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def matches_any(host: Optional[str], domains) -> bool:
    return any(domain_matches(host, domain) for domain in domains or ())
