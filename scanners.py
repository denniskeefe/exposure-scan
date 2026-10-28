"""Automated scanners. Each returns a list of Finding objects.

Live mode needs API keys in the environment:
  HIBP_API_KEY   - Have I Been Pwned v3 (breach exposure)
  BRAVE_API_KEY  - Brave Search API (search / social exposure)
Data broker checks are assisted: they produce unverified findings that the
analyst confirms or rejects during review, because broker sites block bots
and change layouts often.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date

from models import Finding, Subject

SENSITIVE_CLASSES = {
    "Social security numbers", "Credit cards", "Bank account numbers",
    "Passport numbers", "Government issued IDs", "Physical addresses",
    "Dates of birth",
}

SOCIAL_DOMAINS = (
    "facebook.com", "instagram.com", "linkedin.com", "x.com", "twitter.com",
    "tiktok.com", "reddit.com", "youtube.com", "github.com", "pinterest.com",
)

# Consumer people-search / data broker sites the analyst checks.
BROKERS = [
    ("Spokeo", "spokeo.com"), ("Whitepages", "whitepages.com"),
    ("BeenVerified", "beenverified.com"), ("Intelius", "intelius.com"),
    ("PeopleFinders", "peoplefinders.com"), ("Radaris", "radaris.com"),
    ("TruePeopleSearch", "truepeoplesearch.com"),
    ("FastPeopleSearch", "fastpeoplesearch.com"),
    ("MyLife", "mylife.com"), ("US Search", "ussearch.com"),
    ("TruthFinder", "truthfinder.com"), ("PeekYou", "peekyou.com"),
    ("ZabaSearch", "zabasearch.com"), ("Instant Checkmate", "instantcheckmate.com"),
    ("ThatsThem", "thatsthem.com"),
]


def _http_json(url: str, headers: dict) -> tuple[int, object]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def _breach_severity(classes: list[str], breach_date: str) -> int:
    sev = 2
    if "Passwords" in classes:
        sev += 1
    if SENSITIVE_CLASSES & set(classes):
        sev += 1
    try:
        if (date.today() - date.fromisoformat(breach_date)).days < 730:
            sev += 1
    except ValueError:
        pass
    return min(sev, 5)


def scan_breaches(subject: Subject, demo: bool) -> list[Finding]:
    findings: list[Finding] = []
    records: list[tuple[str, dict]] = []
    if demo:
        records = DEMO_BREACHES
    else:
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            raise SystemExit("HIBP_API_KEY not set (use --demo for sample data)")
        for email in subject.emails:
            q = urllib.parse.quote(email)
            status, body = _http_json(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{q}?truncateResponse=false",
                {"hibp-api-key": key, "user-agent": "exposure-scan"},
            )
            if status == 200 and body:
                records += [(email, b) for b in body]
            elif status not in (200, 404):
                raise SystemExit(f"HIBP returned HTTP {status} for {email}")
            time.sleep(1.6)  # HIBP rate limit
    for i, (email, b) in enumerate(records, 1):
        classes = b.get("DataClasses", [])
        sev = _breach_severity(classes, b.get("BreachDate", ""))
        findings.append(Finding(
            id=f"BR-{i:02d}", category="breach", source="Have I Been Pwned",
            title=f"{b['Name']} breach ({b.get('BreachDate', 'unknown')[:4]})",
            detail=f"{email} appears in the {b['Name']} breach. Exposed: {', '.join(classes)}.",
            severity=sev,
            evidence=f"Breach date {b.get('BreachDate', 'n/a')}; verified={b.get('IsVerified', 'n/a')}",
            recommendation=("Rotate the password on this service and anywhere it was reused; "
                            "enable multi-factor authentication."
                            if "Passwords" in classes else
                            "Treat the exposed fields as public; watch for targeted phishing."),
        ))
    return findings


def scan_brokers(subject: Subject, demo: bool) -> list[Finding]:
    findings: list[Finding] = []
    if demo:
        hits = DEMO_BROKER_HITS
    else:
        # Assisted: every broker is an unverified lead for the analyst.
        hits = {name: ("Unverified - analyst to search manually", 3) for name, _ in BROKERS}
    domains = dict(BROKERS)
    for i, (name, (detail, sev)) in enumerate(hits.items(), 1):
        findings.append(Finding(
            id=f"DB-{i:02d}", category="broker", source=name,
            title=f"Listing on {name}",
            detail=detail, severity=sev, evidence=f"Site: {domains.get(name, '')}",
            recommendation=f"Submit an opt-out request to {name} and re-check in 30 days; "
                           "brokers frequently re-list records.",
        ))
    return findings


def scan_social_search(subject: Subject, demo: bool) -> list[Finding]:
    results: list[dict] = []
    if demo:
        results = DEMO_SEARCH
    else:
        key = os.environ.get("BRAVE_API_KEY")
        if not key:
            raise SystemExit("BRAVE_API_KEY not set (use --demo for sample data)")
        place = f" {subject.city} {subject.state}".rstrip()
        queries = [f'"{subject.full_name}"{place}']
        queries += [f'"{e}"' for e in subject.emails]
        queries += [f'"{u}"' for u in subject.usernames]
        queries += [f'"{p}"' for p in subject.phones]
        for q in queries:
            status, body = _http_json(
                "https://api.search.brave.com/res/v1/web/search?count=10&q=" + urllib.parse.quote(q),
                {"X-Subscription-Token": key, "Accept": "application/json"},
            )
            if status != 200:
                raise SystemExit(f"Brave Search returned HTTP {status} for query {q}")
            for r in (body or {}).get("web", {}).get("results", []):
                results.append({"query": q, "url": r["url"], "title": r.get("title", ""),
                                "snippet": r.get("description", "")})
            time.sleep(1.1)
    seen, findings = set(), []
    for r in results:
        if r["url"] in seen:
            continue
        seen.add(r["url"])
        host = urllib.parse.urlparse(r["url"]).netloc.lower()
        social = any(host.endswith(d) for d in SOCIAL_DOMAINS)
        pii_query = not r["query"].startswith('"' + subject.full_name)
        sev = 3 if (pii_query or any(c.isdigit() for c in r["snippet"])) else (2 if social else 1)
        n = len(findings) + 1
        findings.append(Finding(
            id=f"SS-{n:02d}", category="social_search",
            source="Social platform" if social else "Web search",
            title=r["title"][:90] or host,
            detail=f"Surfaced for query {r['query']}: {r['snippet'][:200]}",
            severity=sev, evidence=r["url"],
            recommendation=("Tighten the profile's privacy settings or remove identifying details."
                            if social else
                            "Request removal from the site owner and from search results if the page exposes personal data."),
        ))
    return findings


# ---- Fictional sample data for --demo ------------------------------------
DEMO_BREACHES = [
    ("jordan.sample@example.com", {"Name": "ExampleForum", "BreachDate": "2019-03-14",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"], "IsVerified": True}),
    ("jordan.sample@example.com", {"Name": "SampleRetail", "BreachDate": "2023-08-02",
        "DataClasses": ["Email addresses", "Physical addresses", "Phone numbers", "Dates of birth"],
        "IsVerified": True}),
    ("j.sample@example.org", {"Name": "DemoFitness", "BreachDate": "2021-11-20",
        "DataClasses": ["Email addresses", "Passwords", "Dates of birth"], "IsVerified": True}),
    ("j.sample@example.org", {"Name": "MockMarketing List", "BreachDate": "2020-06-01",
        "DataClasses": ["Email addresses", "Names", "Job titles"], "IsVerified": False}),
]
DEMO_BROKER_HITS = {
    "Spokeo": ("Profile shows age range, home city, relatives, and two email addresses.", 4),
    "Whitepages": ("Listing includes current address and phone number.", 5),
    "BeenVerified": ("Report available with address history and associated people.", 4),
    "TruePeopleSearch": ("Free listing with address, phone, and relatives.", 5),
    "Radaris": ("Profile includes employer and past addresses.", 3),
    "MyLife": ("Public profile with reputation score and location.", 2),
}
DEMO_SEARCH = [
    {"query": '"Jordan Sample" Springfield IL', "url": "https://www.linkedin.com/in/jordan-sample-demo",
     "title": "Jordan Sample - Operations Manager | LinkedIn", "snippet": "Springfield, Illinois. Operations Manager at Example Corp."},
    {"query": '"Jordan Sample" Springfield IL', "url": "https://www.facebook.com/jordan.sample.demo",
     "title": "Jordan Sample | Facebook", "snippet": "Lives in Springfield. Public friends list and photos."},
    {"query": '"jordansample88"', "url": "https://www.reddit.com/user/jordansample88",
     "title": "u/jordansample88", "snippet": "Posts in local and hobby communities; 4 years of history."},
    {"query": '"jordan.sample@example.com"', "url": "https://pastes.example.net/abc123",
     "title": "Mailing list archive", "snippet": "Email and phone 555-0142 appear in a public list archive."},
    {"query": '"Jordan Sample" Springfield IL', "url": "https://www.localnews.example.com/5k-results",
     "title": "Springfield 5K results", "snippet": "Jordan Sample, 38, finished 212th."},
]
