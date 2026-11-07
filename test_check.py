import base64

from check import check_domain, count_spf_lookups, rsa_bits_from_dkim, to_html


class Fake:
    """DNS answers from a dictionary, so every case is exact and offline."""

    def __init__(self, txt=None, mx=None, a=None, ptr=None):
        self._txt, self._mx, self._a, self._ptr = txt or {}, mx or {}, a or {}, ptr or {}

    def txt(self, name):
        return self._txt.get(name, [])

    def mx(self, name):
        return self._mx.get(name, [])

    def a(self, name):
        return self._a.get(name, [])

    def ptr(self, ip):
        return self._ptr.get(ip, [])


def der_key(bits):
    """Minimal DER with an RSA modulus of the given size."""
    modulus = b"\x00" + b"\xab" * (bits // 8)
    return base64.b64encode(b"\x30\x82\x01\x22" + b"\x02\x82" + len(modulus).to_bytes(2, "big") + modulus).decode()


def healthy():
    return Fake(
        txt={"ex.com": ["v=spf1 include:_spf.mail.test ~all"], "_spf.mail.test": ["v=spf1 ip4:1.2.3.4 -all"],
             "_dmarc.ex.com": ["v=DMARC1; p=reject; rua=mailto:d@ex.com"], "selector1._domainkey.ex.com": [f"v=DKIM1; k=rsa; p={der_key(2048)}"],
             "_mta-sts.ex.com": ["v=STSv1; id=1"], "_smtp._tls.ex.com": ["v=TLSRPTv1; rua=mailto:t@ex.com"]},
        mx={"ex.com": [(10, "mx1.ex.com")]}, a={"mx1.ex.com": ["1.2.3.4"]}, ptr={"1.2.3.4": ["mx1.ex.com"]})


def levels(report, area):
    return [f.level for f in report.findings if f.area == area]


def test_a_healthy_domain_scores_top_grade():
    report = check_domain("ex.com", healthy())
    assert report.grade == "A" and report.score == 100
    assert report.spf_lookups == 1
    assert report.dkim_selectors == ["selector1"]


def test_missing_everything_on_a_mail_domain_fails_and_says_what_to_publish():
    report = check_domain("bad.com", Fake(mx={"bad.com": [(10, "mx.bad.com")]}, a={"mx.bad.com": ["9.9.9.9"]}))
    assert report.grade in ("D", "F")
    spf = next(f for f in report.findings if f.area == "SPF")
    assert spf.level == "fail" and 'bad.com. TXT "v=spf1 mx ~all"' == spf.fix
    dmarc = next(f for f in report.findings if f.area == "DMARC")
    assert dmarc.level == "fail" and "_dmarc.bad.com" in dmarc.fix


def test_two_spf_records_are_an_error():
    report = check_domain("d.com", Fake(txt={"d.com": ["v=spf1 -all", "v=spf1 ~all"]}))
    assert "fail" in levels(report, "SPF")


def test_plus_all_is_flagged_as_dangerous():
    report = check_domain("d.com", Fake(txt={"d.com": ["v=spf1 +all"]}))
    assert any("any server" in f.message for f in report.findings)


def test_spf_lookup_limit_counts_through_nested_includes():
    txt = {"d.com": ["v=spf1 include:a.t include:b.t mx a ~all"], "a.t": ["v=spf1 include:c.t include:e.t a mx ~all"],
           "b.t": ["v=spf1 a mx ptr exists:x.t ~all"], "c.t": ["v=spf1 a mx ~all"], "e.t": ["v=spf1 a ~all"]}
    lookups, _ = count_spf_lookups("d.com", Fake(txt=txt))
    assert lookups == 15
    report = check_domain("d.com", Fake(txt=txt))
    assert report.spf_lookups == 15
    assert any("over the limit" in f.message and f.level == "fail" for f in report.findings)


def test_spf_include_loop_ends():
    txt = {"a.t": ["v=spf1 include:b.t ~all"], "b.t": ["v=spf1 include:a.t ~all"]}
    lookups, notes = count_spf_lookups("a.t", Fake(txt=txt))
    assert lookups == 2 and any("loop" in n for n in notes)


def test_dmarc_none_and_partial_percent_are_warnings():
    report = check_domain("d.com", Fake(txt={"_dmarc.d.com": ["v=DMARC1; p=none; rua=mailto:x@d.com"]}))
    assert "warn" in levels(report, "DMARC")
    report = check_domain("d.com", Fake(txt={"_dmarc.d.com": ["v=DMARC1; p=reject; pct=20; rua=mailto:x@d.com"]}))
    assert any("20%" in f.message for f in report.findings)


def test_dmarc_without_report_address_is_noted():
    report = check_domain("d.com", Fake(txt={"_dmarc.d.com": ["v=DMARC1; p=reject"]}))
    assert any("report address" in f.message for f in report.findings)


def test_dkim_key_size_is_read_from_the_record():
    assert rsa_bits_from_dkim(der_key(2048)) == 2048
    assert rsa_bits_from_dkim(der_key(1024)) == 1024
    txt = {"selector1._domainkey.d.com": [f"v=DKIM1; p={der_key(1024)}"]}
    assert "warn" in levels(check_domain("d.com", Fake(txt=txt)), "DKIM")


def test_revoked_dkim_selector_is_not_called_a_problem():
    txt = {"s1._domainkey.d.com": ["v=DKIM1; p="]}
    assert levels(check_domain("d.com", Fake(txt=txt)), "DKIM") == ["info"]


def test_null_mx_is_understood_and_parked_domain_gets_the_right_spf_advice():
    report = check_domain("d.com", Fake(mx={"d.com": [(0, "")]}))
    assert any("accepts no mail" in f.message for f in report.findings)
    assert any(f.fix == 'd.com. TXT "v=spf1 -all"' for f in report.findings)


def test_reverse_dns_mismatch_and_missing_ptr():
    base = dict(mx={"d.com": [(10, "mx.d.com")]}, a={"mx.d.com": ["1.1.1.1"]})
    assert "warn" in levels(check_domain("d.com", Fake(**base)), "Reverse DNS")
    report = check_domain("d.com", Fake(**base, ptr={"1.1.1.1": ["other.host"]}))
    assert any("resolve back" in f.message for f in report.findings)


def test_mx_host_without_address_is_a_failure():
    report = check_domain("d.com", Fake(mx={"d.com": [(10, "gone.d.com")]}))
    assert "fail" in levels(report, "MX")


def test_html_report_escapes_values_from_dns():
    report = check_domain("d.com", Fake(txt={"d.com": ["v=spf1 include:<script>x ~all"]}))
    page = to_html(report)
    assert "<script>x" not in page
    assert "<title>Email check: d.com</title>" in page
