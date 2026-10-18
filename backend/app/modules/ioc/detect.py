"""Prepoznavanje i izvlačenje IOC-ova (IP, domen, URL, hash) iz teksta.

Analitičari često lepe "defangovane" indikatore (hxxp://evil[.]com), pa
sve prvo vraćamo u normalan oblik (refang), a za prikaz u UI-ju opet
pravimo bezbednu verziju (defang).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


HASH_TYPES = {IocType.MD5, IocType.SHA1, IocType.SHA256}
IP_TYPES = {IocType.IPV4, IocType.IPV6}


@dataclass(frozen=True)
class Ioc:
    value: str
    type: IocType
    # True za privatne, loopback, link-local i slične adrese koje nema smisla slati napolje
    internal: bool = False


_REFANG_RULES = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*:\s*//\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]", re.I), "@"),
]


def refang(text: str) -> str:
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Bezbedan prikaz: ne može slučajno da se klikne ili otvori."""
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]")


_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`]+", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b", re.I
)

# Nastavci fajlova koji bi inače izgledali kao domen (invoice.pdf, run.ps1...)
_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "msi",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt",
    "log", "csv", "json", "xml", "html", "htm", "png", "jpg", "jpeg", "gif", "iso",
    "img", "tmp", "dat", "bin", "cfg", "ini", "yml", "yaml", "md",
}

_HASH_BY_LEN = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}
_TRAILING_PUNCT = ".,;:!?)]}'\""


def _is_internal_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def classify(raw: str) -> Ioc | None:
    """Prepoznaje tip jednog indikatora. Vraća None ako nije ništa poznato."""
    value = refang(raw.strip()).strip(_TRAILING_PUNCT)
    if not value:
        return None

    if _URL_RE.fullmatch(value):
        return Ioc(value, IocType.URL)

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        kind = IocType.IPV4 if ip.version == 4 else IocType.IPV6
        return Ioc(ip.compressed, kind, internal=_is_internal_ip(ip))

    if _HASH_RE.fullmatch(value):
        return Ioc(value.lower(), _HASH_BY_LEN[len(value)])

    if _DOMAIN_RE.fullmatch(value):
        tld = value.rsplit(".", 1)[-1].lower()
        if tld not in _FILE_EXTENSIONS:
            internal = tld in {"local", "lan", "internal", "corp", "home", "localdomain"}
            return Ioc(value.lower(), IocType.DOMAIN, internal=internal)

    return None


def extract(text: str, limit: int = 50) -> list[Ioc]:
    """Izvlači sve IOC-ove iz slobodnog teksta (log, mejl, alert), bez duplikata."""
    text = refang(text)
    found: list[Ioc] = []
    seen: set[tuple[str, IocType]] = set()

    def add(candidate: str) -> None:
        ioc = classify(candidate)
        if ioc and (ioc.value, ioc.type) not in seen:
            seen.add((ioc.value, ioc.type))
            found.append(ioc)

    # URL-ove i mejl adrese vadimo prve i brišemo ih iz teksta, da se njihov
    # domen ne bi duplirao kao poseban IOC.
    for match in _URL_RE.finditer(text):
        add(match.group().rstrip(_TRAILING_PUNCT))
    text = _URL_RE.sub(" ", text)
    text = _EMAIL_RE.sub(" ", text)

    for pattern in (_HASH_RE, _IPV4_RE, _IPV6_RE):
        for match in pattern.finditer(text):
            add(match.group())
        text = pattern.sub(" ", text)

    for match in _DOMAIN_RE.finditer(text):
        add(match.group())

    return found[:limit]
