#!/usr/bin/env python3
"""Compile every rule in rules/ with pySigma's SQLite backend and run it against
tests/samples.jsonl (synthetic requests, no real traffic). Each sample lists the
rules it must trigger; any other match, or a missing one, fails the run.

Field map: cs-user-agent=ua, c-ip=ip, cs-uri-stem / cs-uri-query = path split at
the first '?', timestamp=ts."""
import json, pathlib, sqlite3, sys
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

ROOT = pathlib.Path(__file__).resolve().parent.parent
# rule file -> short key used in samples.jsonl
KEYS = {
    "web_ai_crawler_ua.yml": "web_ai_crawler_ua",
    "web_ai_crawler_ua_rotation.yml": "rotation",
    "web_ai_crawler_ua_secret_files.yml": "secret_files",
    "web_vite_devserver_file_read_probe.yml": "vite_probe",
    "web_vite_devserver_file_read_secrets.yml": "vite_secrets",
}

samples = [json.loads(l) for l in (ROOT / "tests/samples.jsonl").read_text().splitlines() if l.strip()]
db = sqlite3.connect(":memory:")
db.execute('CREATE TABLE logs (timestamp TEXT, "c-ip" TEXT, "cs-user-agent" TEXT, "cs-uri-stem" TEXT, "cs-uri-query" TEXT)')
for s in samples:
    stem, _, query = s["path"].partition("?")
    db.execute("INSERT INTO logs (rowid, timestamp, \"c-ip\", \"cs-user-agent\", \"cs-uri-stem\", \"cs-uri-query\") VALUES (?,?,?,?,?,?)",
               (s["id"], s["ts"], s["ip"], s["ua"], stem, query))

base = (ROOT / "rules/web/web_ai_crawler_ua.yml").read_text()
backend = sqliteBackend()
failures = 0
for fname, key in KEYS.items():
    text = (ROOT / "rules/web" / fname).read_text()
    if key == "rotation":            # a correlation needs its base rule loaded alongside
        text = base + "\n---\n" + text
    queries = backend.convert(SigmaCollection.from_yaml(text))
    sql = queries[-1]
    if sql.startswith("WITH"):      # correlation output: collect contributing rows
        cur = db.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        got = {int(e.split(":")[-1]) for r in rows for e in json.loads(r[cols.index("event_ids")])}
    else:
        got = {r[0] for r in db.execute(sql.replace("SELECT *", "SELECT rowid", 1))}
    want = {s["id"] for s in samples if key in s["expect"]}
    ok = got == want
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {key:18} matched {sorted(got)}" + ("" if ok else f"  expected {sorted(want)}"))
sys.exit(1 if failures else 0)
