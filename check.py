"""Checks a domain's email setup and says exactly what to fix.

Covers MX, SPF (with the 10-lookup limit), DKIM selectors and key size, DMARC, MTA-STS, TLS-RPT and
reverse DNS of the mail hosts. Findings carry a severity and, where possible, the record to publish.
It only reads public DNS and sends no mail. `python check.py example.com --html report.html`
"""
from __future__ import annotations

import argparse
import base64
import html
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Protocol

import dns.exception
import dns.resolver
import dns.reversename

COMMON_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault", "zoho", "sendgrid"]
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")
SPF_LIMIT = 10


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def a(self, name: str) -> list[str]: ...
    def ptr(self, ip: str) -> list[str]: ...


class DnsResolver:
    def __init__(self, timeout: float = 5.0):
        self.r = dns.resolver.Resolver()
        self.r.lifetime = timeout

    def _query(self, name: str, rtype: str):
        try:
            return list(self.r.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.name.EmptyLabel):
            return []

    def txt(self, name: str) -> list[str]:
        return [b"".join(a.strings).decode("utf-8", "replace") for a in self._query(name, "TXT")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted((a.preference, str(a.exchange).rstrip(".").lower()) for a in self._query(name, "MX"))

    def a(self, name: str) -> list[str]:
        return [str(a) for a in self._query(name, "A")]

    def ptr(self, ip: str) -> list[str]:
        return [str(a).rstrip(".").lower() for a in self._query(str(dns.reversename.from_address(ip)), "PTR")]


@dataclass
class Finding:
    area: str
    level: str  # ok, warn, fail, info
    message: str
    fix: str = ""


@dataclass
class Report:
    domain: str
    findings: list[Finding] = field(default_factory=list)
    spf_lookups: int | None = None
    dkim_selectors: list[str] = field(default_factory=list)

    def add(self, area: str, level: str, message: str, fix: str = "") -> None:
        self.findings.append(Finding(area, level, message, fix))

    @property
    def score(self) -> int:
        weights = {"fail": 25, "warn": 8}
        return max(0, 100 - sum(weights.get(f.level, 0) for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 55 else "D" if s >= 35 else "F"


# ---------------------------------------------------------------- SPF
def count_spf_lookups(domain: str, resolver: Resolver, seen: set[str] | None = None, depth: int = 0) -> tuple[int, list[str]]:
    """Counts DNS-querying mechanisms through nested includes, as receivers do under RFC 7208."""
    seen = seen if seen is not None else set()
    notes: list[str] = []
    if domain in seen or depth > 12:
        return 0, [f"include loop at {domain}"] if domain in seen else notes
    seen.add(domain)
    records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
    if not records:
        return 0, [f"{domain} has no SPF record"]
    total = 0
    for term in records[0].split()[1:]:
        term = term.lstrip("+-~?").lower()
        name, _, value = term.partition(":") if ":" in term else term.partition("=")
        name = name.split("/")[0]
        if name in LOOKUP_MECHANISMS:
            total += 1
            if name in ("include", "redirect") and value:
                sub, sub_notes = count_spf_lookups(value, resolver, seen, depth + 1)
                total += sub
                notes += sub_notes
    return total, notes


def check_spf(domain: str, resolver: Resolver, report: Report, has_mx: bool) -> None:
    records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
    if not records:
        if has_mx:
            report.add("SPF", "fail", "No SPF record, so receivers can't tell which servers may send for this domain.",
                       f'{domain}. TXT "v=spf1 mx ~all"')
        else:
            report.add("SPF", "warn", "No SPF record on a domain that doesn't appear to send mail.", f'{domain}. TXT "v=spf1 -all"')
        return
    if len(records) > 1:
        report.add("SPF", "fail", f"{len(records)} SPF records found. Only one is allowed, so receivers treat this as an error.",
                   "Merge them into a single TXT record.")
    record = records[0]
    lookups, notes = count_spf_lookups(domain, resolver)
    report.spf_lookups = lookups
    for note in notes:
        report.add("SPF", "warn", note)
    if lookups > SPF_LIMIT:
        report.add("SPF", "fail", f"{lookups} DNS lookups, over the limit of {SPF_LIMIT}. Receivers return permerror and SPF stops protecting you.",
                   "Remove unused includes or flatten the record.")
    else:
        report.add("SPF", "ok", f"SPF record found, {lookups} of {SPF_LIMIT} DNS lookups used.")
    ending = re.search(r"([+\-~?])?all\b", record)
    if not ending:
        report.add("SPF", "warn", "The record doesn't end in an 'all' mechanism.", "End the record with ~all or -all.")
    elif ending.group(1) in (None, "+"):
        report.add("SPF", "fail", "The record ends in +all, which lets any server send as this domain.", "End it with ~all or -all.")
    elif ending.group(1) == "?":
        report.add("SPF", "warn", "The record ends in ?all, which gives receivers no guidance.", "End it with ~all or -all.")


# ---------------------------------------------------------------- DKIM
def rsa_bits_from_dkim(public_key_b64: str) -> int | None:
    """Reads the modulus length from the DER key in a DKIM record."""
    try:
        der = base64.b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
    except ValueError:
        return None
    # SubjectPublicKeyInfo: the modulus is the first long INTEGER after the BIT STRING header.
    at = der.find(b"\x02\x82")
    if at != -1:
        return (int.from_bytes(der[at + 2:at + 4], "big") - (der[at + 4] == 0)) * 8
    at = der.find(b"\x02\x81")
    if at != -1:
        return (der[at + 2] - (der[at + 3] == 0)) * 8
    return None


def check_dkim(domain: str, resolver: Resolver, report: Report, selectors: list[str], has_mx: bool) -> None:
    for selector in selectors:
        for text in resolver.txt(f"{selector}._domainkey.{domain}"):
            if "p=" not in text:
                continue
            tags = dict(p.strip().split("=", 1) for p in text.split(";") if "=" in p)
            key = tags.get("p", "").replace(" ", "")
            report.dkim_selectors.append(selector)
            if not key:
                report.add("DKIM", "info", f"Selector '{selector}' is published with an empty key, so it has been revoked.")
                continue
            if tags.get("k", "rsa").strip().lower() == "rsa":
                bits = rsa_bits_from_dkim(key)
                if bits and bits < 1024:
                    report.add("DKIM", "fail", f"Selector '{selector}' uses a {bits}-bit key, which receivers can reject.", "Rotate to a 2048-bit key.")
                elif bits and bits < 2048:
                    report.add("DKIM", "warn", f"Selector '{selector}' uses a {bits}-bit key.", "Rotate to a 2048-bit key.")
                else:
                    report.add("DKIM", "ok", f"Selector '{selector}' found" + (f", {bits}-bit key." if bits else "."))
            else:
                report.add("DKIM", "ok", f"Selector '{selector}' found, {tags['k'].strip()} key.")
    if not report.dkim_selectors:
        level = "warn" if has_mx else "info"
        report.add("DKIM", level, f"No key found under {len(selectors)} common selector names. DKIM may still exist under another name.",
                   "Check the selector in the DKIM-Signature header of a sent message.")


# ---------------------------------------------------------------- DMARC
def check_dmarc(domain: str, resolver: Resolver, report: Report) -> None:
    records = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    suggestion = f'_dmarc.{domain}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"'
    if not records:
        report.add("DMARC", "fail", "No DMARC record. Bulk senders are required to have one by large mailbox providers, and spoofing goes unreported.", suggestion)
        return
    if len(records) > 1:
        report.add("DMARC", "fail", "More than one DMARC record, so receivers ignore DMARC entirely.", "Keep a single record.")
    tags = {k.strip().lower(): v.strip() for k, v in (p.split("=", 1) for p in records[0].split(";") if "=" in p)}
    policy = tags.get("p", "").lower()
    if policy in ("reject", "quarantine"):
        pct = tags.get("pct", "100")
        if pct != "100":
            report.add("DMARC", "warn", f"Policy is {policy}, but only applied to {pct}% of failing mail.", "Raise pct to 100 once reports look clean.")
        else:
            report.add("DMARC", "ok", f"Policy is {policy}.")
    elif policy == "none":
        report.add("DMARC", "warn", "Policy is none, so failing mail is monitored but still delivered.", "Move to quarantine, then reject, once reports look clean.")
    else:
        report.add("DMARC", "fail", "The record has no valid policy.", suggestion)
    if "rua" not in tags:
        report.add("DMARC", "warn", "No aggregate report address, so you won't see who sends as your domain.", f"Add rua=mailto:dmarc@{domain}")


# ---------------------------------------------------------------- transport
def check_transport(domain: str, resolver: Resolver, report: Report, mx: list[tuple[int, str]]) -> None:
    sts = [t for t in resolver.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    if sts:
        report.add("MTA-STS", "ok", "MTA-STS is published, so senders are told to require TLS.")
    elif mx:
        report.add("MTA-STS", "info", "No MTA-STS. Inbound TLS can be stripped by an attacker on the path.", "Publish _mta-sts TXT and a policy file over HTTPS.")
    rpt = [t for t in resolver.txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    if rpt:
        report.add("TLS-RPT", "ok", "TLS reporting is on.")
    elif mx:
        report.add("TLS-RPT", "info", "No TLS reporting, so TLS delivery failures go unnoticed.", f'_smtp._tls.{domain}. TXT "v=TLSRPTv1; rua=mailto:tls@{domain}"')


def check_reverse_dns(resolver: Resolver, report: Report, mx: list[tuple[int, str]]) -> None:
    for _, host in mx[:3]:
        addresses = resolver.a(host)
        if not addresses:
            report.add("MX", "fail", f"{host} has no A record, so it can't receive mail over IPv4.")
            continue
        names = resolver.ptr(addresses[0])
        if not names:
            report.add("Reverse DNS", "warn", f"{addresses[0]} ({host}) has no PTR record, which many receivers treat as a spam signal.",
                       "Ask the hosting provider to set a PTR record.")
        elif not any(name == host or resolver_forward_matches(name, addresses[0], resolver) for name in names):
            report.add("Reverse DNS", "warn", f"{addresses[0]} ({host}) reverses to {names[0]}, which doesn't resolve back to the same address.",
                       "Make the forward and reverse records match.")
        else:
            report.add("Reverse DNS", "ok", f"{host} has matching forward and reverse DNS.")


def resolver_forward_matches(name: str, ip: str, resolver: Resolver) -> bool:
    return ip in resolver.a(name)


def check_domain(domain: str, resolver: Resolver | None = None, selectors: list[str] | None = None) -> Report:
    resolver = resolver or DnsResolver()
    domain = domain.strip().lower().rstrip(".")
    report = Report(domain)
    mx = resolver.mx(domain)
    null_mx = mx == [(0, "")]
    if null_mx:
        report.add("MX", "info", "Null MX, so this domain declares it accepts no mail.")
        mx = []
    elif mx:
        report.add("MX", "ok", f"{len(mx)} mail server(s), lowest preference: {mx[0][1]}.")
    else:
        report.add("MX", "info", "No MX records. This domain can't receive mail unless it falls back to an A record.")
    has_mx = bool(mx)
    check_spf(domain, resolver, report, has_mx)
    check_dkim(domain, resolver, report, selectors or COMMON_SELECTORS, has_mx)
    check_dmarc(domain, resolver, report)
    check_transport(domain, resolver, report, mx)
    if mx:
        check_reverse_dns(resolver, report, mx)
    return report


# ---------------------------------------------------------------- output
CSS = """
body{margin:0;background:#f4f5f7;color:#1b2430;font:15px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:980px;margin:auto;padding:24px 16px}
.top{display:flex;align-items:center;gap:18px;background:#fff;border:1px solid #e1e5ea;border-radius:8px;padding:16px 20px;margin-bottom:14px}
.grade{width:72px;height:72px;border-radius:8px;display:grid;place-items:center;font-size:40px;font-weight:700;color:#fff}
h1{font-size:24px;margin:0}.sub{color:#66707e}
.item{background:#fff;border:1px solid #e1e5ea;border-left:6px solid #999;border-radius:6px;padding:10px 14px;margin-bottom:8px}
.ok{border-left-color:#14713d}.warn{border-left-color:#c98a00}.fail{border-left-color:#b3341f}.info{border-left-color:#7b8794}
.area{font-weight:600;margin-right:6px}.fix{display:block;margin-top:4px;color:#3d4957;font:13px Consolas,monospace;overflow-wrap:anywhere}
"""
GRADE_COLOURS = {"A": "#14713d", "B": "#4c8c2b", "C": "#c98a00", "D": "#c9600a", "F": "#b3341f"}


def to_html(report: Report) -> str:
    order = {"fail": 0, "warn": 1, "info": 2, "ok": 3}
    items = "".join(
        f'<div class="item {f.level}"><span class="area">{html.escape(f.area)}</span>{html.escape(f.message)}'
        + (f'<span class="fix">{html.escape(f.fix)}</span>' if f.fix else "") + "</div>"
        for f in sorted(report.findings, key=lambda f: order[f.level]))
    return (f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>Email check: {html.escape(report.domain)}</title><style>{CSS}</style><main>"
            f'<div class="top"><div class="grade" style="background:{GRADE_COLOURS[report.grade]}">{report.grade}</div>'
            f'<div><h1>{html.escape(report.domain)}</h1><div class="sub">Score {report.score} of 100. Public DNS only, no mail sent.</div></div></div>{items}</main></html>')


def main() -> None:
    ap = argparse.ArgumentParser(description="Check a domain's email authentication and transport setup")
    ap.add_argument("domain")
    ap.add_argument("--selector", action="append", help="DKIM selector to try, can repeat")
    ap.add_argument("--html", help="write an HTML report to this path")
    args = ap.parse_args()
    report = check_domain(args.domain, selectors=args.selector)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(report))
    print(json.dumps({"domain": report.domain, "grade": report.grade, "score": report.score, "spf_lookups": report.spf_lookups,
                      "dkim_selectors": report.dkim_selectors, "findings": [asdict(f) for f in report.findings]}, indent=2))


if __name__ == "__main__":
    main()
