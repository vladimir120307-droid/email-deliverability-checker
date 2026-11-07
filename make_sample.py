"""Writes the sample report: the real checker run on made-up DNS answers for a fictional domain."""
from pathlib import Path

from check import check_domain, to_html
from test_check import Fake, der_key

txt = {
    "example-shop.test": ["v=spf1 include:a.mail.test include:b.mail.test include:crm.test include:news.test mx a ~all"],
    "a.mail.test": ["v=spf1 include:a2.mail.test mx a ~all"], "a2.mail.test": ["v=spf1 a mx ~all"],
    "b.mail.test": ["v=spf1 a mx ~all"], "crm.test": ["v=spf1 a mx ~all"], "news.test": ["v=spf1 a mx ptr ~all"],
    "selector1._domainkey.example-shop.test": [f"v=DKIM1; k=rsa; p={der_key(1024)}"],
}
report = check_domain("example-shop.test", Fake(txt=txt, mx={"example-shop.test": [(10, "mail.example-shop.test")]}, a={"mail.example-shop.test": ["192.0.2.10"]}))
Path("results").mkdir(exist_ok=True)
Path("results/sample-report.html").write_text(to_html(report), encoding="utf-8")
print(report.grade, report.score, report.spf_lookups)
