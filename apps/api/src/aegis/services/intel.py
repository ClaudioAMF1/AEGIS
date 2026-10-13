"""Threat-intelligence matching and optional external reputation lookups.

Indicators are auxiliary signals. A match raises context on an event (``intel.*`` fields that
rules may use) but never, on its own, declares a compromise.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.models import IntelLookup, Severity, ThreatIndicator

log = logging.getLogger(__name__)

INDICATOR_TYPES = {"ipv4", "ipv6", "cidr", "domain", "sha256"}


def classify(value: str) -> str | None:
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
    except ValueError:
        return None
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return "sha256"
    if "." in value and all(
        part and len(part) <= 63 and part.replace("-", "").isalnum() for part in value.split(".")
    ):
        return "domain"
    return None


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


@dataclass
class Match:
    indicator: ThreatIndicator
    observed: str
    field: str


def match_values(db: Session, observed: dict[str, str]) -> list[Match]:
    """Match observed values (field -> value) against active indicators."""
    if not observed:
        return []
    now = utcnow()
    values = {v.lower() for v in observed.values()}
    rows = db.scalars(
        select(ThreatIndicator).where(
            or_(ThreatIndicator.value.in_(values), ThreatIndicator.type == "cidr"),
            or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
        )
    ).all()
    matches: list[Match] = []
    for indicator in rows:
        for field, value in observed.items():
            if indicator.type == "cidr":
                try:
                    if ipaddress.ip_address(value) in ipaddress.ip_network(indicator.value):
                        matches.append(Match(indicator, value, field))
                except ValueError:
                    continue
            elif indicator.value == value.lower():
                matches.append(Match(indicator, value, field))
    if matches:
        db.execute(
            update(ThreatIndicator)
            .where(ThreatIndicator.id.in_({m.indicator.id for m in matches}))
            .values(hits=ThreatIndicator.hits + 1, last_seen_at=now)
        )
    return matches


def enrichment_for(matches: list[Match]) -> dict[str, Any]:
    if not matches:
        return {}
    top = max(matches, key=lambda m: (Severity(m.indicator.severity).rank, m.indicator.confidence))
    return {
        "intel.matched": True,
        "intel.indicator": top.observed,
        "intel.severity": top.indicator.severity,
        "intel.confidence": top.indicator.confidence,
        "intel.source": top.indicator.source,
        "intel_matches": [
            {
                "field": m.field,
                "value": m.observed,
                "type": m.indicator.type,
                "source": m.indicator.source,
                "confidence": m.indicator.confidence,
                "severity": m.indicator.severity,
                "description": m.indicator.description[:200],
                "indicator_id": str(m.indicator.id),
            }
            for m in matches
        ],
    }


# ---------------------------------------------------------------------------
# External lookups (opt-in). Only a fixed allow-list of HTTPS endpoints is ever contacted and
# user input is never used to build a host name, which prevents SSRF.
# ---------------------------------------------------------------------------

_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
_CACHE_TTL = timedelta(hours=24)


@dataclass
class LookupResult:
    provider: str
    indicator: str
    verdict: str
    score: int | None
    data: dict[str, Any]
    queried_at: str
    cached: bool


def lookup_ip(db: Session, value: str) -> LookupResult:
    settings = get_settings()
    if not is_public_ip(value):
        return LookupResult(
            "local",
            value,
            "not_applicable",
            None,
            {"reason": "private, reserved or invalid address"},
            utcnow().isoformat(),
            False,
        )
    cached = db.scalar(
        select(IntelLookup).where(
            IntelLookup.provider == "abuseipdb", IntelLookup.indicator == value
        )
    )
    if cached is not None and cached.expires_at > utcnow():
        return LookupResult(
            cached.provider,
            value,
            cached.verdict,
            cached.score,
            cached.data,
            cached.queried_at.isoformat(),
            True,
        )
    if not settings.intel_external_enabled or settings.abuseipdb_api_key is None:
        return LookupResult(
            "abuseipdb",
            value,
            "disabled",
            None,
            {"reason": "external enrichment is disabled"},
            utcnow().isoformat(),
            False,
        )
    query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
    request = urllib.request.Request(  # noqa: S310 - fixed https endpoint
        f"{_ABUSEIPDB}?{query}",
        headers={
            "Key": settings.abuseipdb_api_key.get_secret_value(),
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            body = json.loads(response.read(200_000))
    except Exception as exc:
        log.warning("abuseipdb lookup failed: %s", type(exc).__name__)
        return LookupResult(
            "abuseipdb",
            value,
            "error",
            None,
            {"reason": type(exc).__name__},
            utcnow().isoformat(),
            False,
        )
    data = body.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "unknown"
    keep = {
        k: data.get(k)
        for k in ("countryCode", "isp", "usageType", "totalReports", "lastReportedAt", "isTor")
    }
    now = utcnow()
    if cached is None:
        cached = IntelLookup(provider="abuseipdb", indicator=value)
        db.add(cached)
    cached.verdict, cached.score, cached.data = verdict, score, keep
    cached.queried_at, cached.expires_at = now, now + _CACHE_TTL
    db.commit()
    return LookupResult("abuseipdb", value, verdict, score, keep, now.isoformat(), False)
