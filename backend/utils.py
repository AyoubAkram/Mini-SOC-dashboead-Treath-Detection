"""
Utilities
Timestamp parsing, integrity hashing and small helpers shared by the pipeline.
"""

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(dt: datetime) -> datetime:
    """Return an aware UTC datetime (naive values are assumed to be UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _guess_year(month: int, day: int, hour: int, minute: int, second: int,
                now: Optional[datetime] = None) -> datetime:
    """
    Formats like BSD syslog carry no year. Assume the current year, and fall
    back to the previous one when that would put the event in the future
    (e.g. a December line read in January).
    """
    now = now or utcnow()
    # Walk back from the current year: skips future dates, and years where the
    # date does not exist (Feb 29 outside a leap year).
    for year in range(now.year, now.year - 9, -1):
        try:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            continue
        if dt <= now + timedelta(days=1):
            return dt
    raise ValueError(f"invalid date: month={month} day={day}")


def parse_bsd_timestamp(text: str, now: Optional[datetime] = None) -> datetime:
    """Parse 'Jun 14 15:16:01' (RFC 3164 / auth.log / kernel log)."""
    month_name, day, clock = text.split()
    hour, minute, second = (int(p) for p in clock.split(":"))
    return _guess_year(MONTHS[month_name], int(day), hour, minute, second, now)


def parse_iso_timestamp(text: str) -> datetime:
    """Parse ISO 8601 / RFC 3339, including a trailing 'Z'."""
    text = str(text).strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    return to_utc(datetime.fromisoformat(text))


def parse_apache_timestamp(text: str) -> datetime:
    """Parse '14/Jun/2026:15:16:01 +0000' (Apache / Nginx combined log)."""
    return to_utc(datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z"))


def parse_snort_timestamp(text: str, now: Optional[datetime] = None) -> datetime:
    """Parse '06/14-15:16:01.123456' or '06/14/26-15:16:01.123456' (Snort fast alert)."""
    date_part, clock = text.split("-", 1)
    pieces = date_part.split("/")
    hour, minute, second = clock.split(":")
    sec = int(float(second))
    if len(pieces) == 3:
        year = int(pieces[2])
        year += 2000 if year < 100 else 0
        return datetime(year, int(pieces[0]), int(pieces[1]), int(hour), int(minute), sec,
                        tzinfo=timezone.utc)
    return _guess_year(int(pieces[0]), int(pieces[1]), int(hour), int(minute), sec, now)


def parse_epoch(value) -> datetime:
    """Parse a Unix epoch (seconds, int/float/str) such as Zeek's 'ts'."""
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def parse_any_timestamp(value) -> datetime:
    """Best-effort parser for JSON sources that mix epoch and ISO timestamps."""
    if isinstance(value, (int, float)):
        return parse_epoch(value)
    text = str(value).strip()
    try:
        return parse_epoch(text)
    except ValueError:
        return parse_iso_timestamp(text)


def sha256_batch(lines: Iterable[str]) -> str:
    """
    SHA-256 over the raw lines of a batch, in order.
    Each line is length-prefixed so that moving a boundary between two lines
    ('ab','c' vs 'a','bc') changes the digest.
    """
    digest = hashlib.sha256()
    for line in lines:
        data = line.encode("utf-8", errors="replace")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b":")
        digest.update(data)
    return digest.hexdigest()


def clean_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical IP string, or None for empty / placeholder / invalid values."""
    if not value:
        return None
    value = str(value).strip()
    if value in ("-", "::", "0.0.0.0", "(empty)"):
        return None
    if value.startswith("::ffff:"):
        value = value[7:]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def to_int(value) -> Optional[int]:
    """Convert to int, returning None for missing / placeholder values."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Python's ip.is_private also covers documentation ranges such as 203.0.113.0/24,
# which the generator uses for attackers, so internal networks are listed here.
INTERNAL_NETWORKS = [ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]


def is_private_ip(value: Optional[str]) -> bool:
    """True for internal addresses (RFC 1918, loopback, link-local, IPv6 ULA)."""
    try:
        ip = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)
