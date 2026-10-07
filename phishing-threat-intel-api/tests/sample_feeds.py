"""SYNTHETIC TEST DATA ONLY - NOT REAL THREAT INTELLIGENCE.

These payloads imitate the *format* of each external feed so parsers can be
tested without network access. All hosts use reserved example domains
(example.com/.net/.org, RFC 2606) and none of the values were observed in a
real feed. Never load this data into a real database.
"""

import json

OPENPHISH_TXT = """\
https://login.example.com/verify
# a comment line
http://secure-update.example.net/account

https://login.example.com/verify
"""

PHISHSTATS_PAGE = json.dumps([
    {"id": 101, "url": "https://login.example.com/verify", "date": "2026-09-01T10:00:00.000Z",
     "ip": "203.0.113.5", "countrycode": "XX", "score": 7.2, "title": "Sign in"},
    {"id": 102, "url": "http://secure-update.example.net/account", "date": "2026-09-02T11:30:00.000Z"},
    {"id": 103, "url": "javascript:alert(1)", "date": "2026-09-02T11:30:00.000Z"},
    {"id": 104},
])

PHISHTANK_JSON = json.dumps([
    {"phish_id": "9001", "url": "https://login.example.com/verify", "submission_time": "2026-08-30T08:00:00+00:00",
     "verified": "yes", "verification_time": "2026-08-30T09:00:00+00:00", "online": "yes",
     "target": "Example Bank", "phish_detail_url": "http://www.phishtank.com/phish_detail.php?phish_id=9001",
     "details": [{"ip_address": "203.0.113.5", "country": "XX", "announcing_network": "64500"}]},
    {"phish_id": "9002", "url": "https://example.org/signin?session=1", "submission_time": "2026-08-31T08:00:00+00:00",
     "verified": "yes", "online": "no", "target": "Other", "details": []},
])

URLHAUS_JSON = json.dumps({
    "query_status": "ok",
    "urls": [
        {"id": "5001", "urlhaus_reference": "https://urlhaus.abuse.ch/url/5001/",
         "url": "https://files.example.net/payload.exe", "url_status": "online", "threat": "malware_download",
         "date_added": "2026-09-03 12:00:00 UTC", "tags": ["exe", "loader"], "reporter": "tester"},
        {"id": "5002", "url": "http://example.com/phish", "url_status": "offline", "threat": "phishing",
         "date_added": "2026-09-04 12:00:00 UTC", "tags": None},
    ],
})
