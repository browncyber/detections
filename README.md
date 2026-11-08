# BCS detections

Sigma rules from [Brown Cyber Services](https://browncyber.com) for web traffic that pretends to be something it isn't. The rules detect behavior, not IP addresses: an address list goes stale in days, and a scanner can't easily drop the habit that gives it away.

Every rule here comes from traffic I saw on disclosed honeypot sensors that I run, and each one was tested against that traffic before publication.

## Rules

| Rule | Level | What it catches |
|---|---|---|
| [`web_ai_crawler_ua`](rules/web/web_ai_crawler_ua.yml) | informational | A user agent that claims to be a known AI or search crawler. This is the base rule for the next one. Most matches are real crawlers, so don't alert on it alone. |
| [`web_ai_crawler_ua_rotation`](rules/web/web_ai_crawler_ua_rotation.yml) | medium | One client address showing three or more different crawler user agents within ten minutes. Real crawlers keep one identity; scanners rotate through crawler names to blend in or to get past bot allowlists. |
| [`web_ai_crawler_ua_secret_files`](rules/web/web_ai_crawler_ua_secret_files.yml) | high | A crawler user agent requesting `/.env`, `/.git/config` or similar secret files. Crawlers follow links; they have no reason to ask for these paths. |
| [`web_vite_devserver_file_read_probe`](rules/web/web_vite_devserver_file_read_probe.yml) | medium | Query strings from the 2025 Vite dev-server file-read bypasses (CVE-2025-30208, CVE-2025-31125, CVE-2025-31486). A production site never sends them. |
| [`web_vite_devserver_file_read_secrets`](rules/web/web_vite_devserver_file_read_secrets.yml) | high | The same markers, or a plain `?raw`, aimed at `.env`, `/etc/passwd`, `win.ini` or Vite's `/@fs/` prefix. This is the exploitation attempt. |

All rules use the generic `webserver` log source with the standard fields (`cs-user-agent`, `c-ip`, `cs-uri-stem`, `cs-uri-query`). The rotation rule is a Sigma correlation (`value_count`), so it needs a backend that supports correlations, and the base rule must be loaded with it.

## How they were tested

Before publication I ran all five rules, compiled to SQL with pySigma's SQLite backend, against 16 days of honeypot traffic (4,733 requests, 23 October to 7 November 2026).

- The rotation rule fired on 14 sources. The eight largest were all scanners my own labeling had already flagged for wearing several crawler names, and seven of those sat on one public cloud network.
- The secret-files rule matched 103 requests. 70 of them claimed to be Googlebot: 39 came from other networks, and 31 arrived before I logged networks at all. Real Googlebot (AS15169) never requested a secret path. In practice the rule caught Googlebot spoofers.
- The two Vite rules matched every bypass attempt in the data. Those probes also wore crawler names (Bravebot, Qwenbot, Amazonbot), so the same scanners trip both families.
- No false positives turned up. Real Googlebot appeared from only seven addresses, so the known limit of the rotation rule, below, has not been tested at scale.

The repo carries its own check: [`tests/run_tests.py`](tests/run_tests.py) compiles each rule and runs it against [`tests/samples.jsonl`](tests/samples.jsonl), synthetic requests that list which rules each one should and shouldn't trigger. GitHub Actions runs it and `sigma check` on every push.

```
pip install "sigma-cli==4.0.0" "pysigma-backend-sqlite==2.1.1"
sigma check -x escaped_wildcard rules/
python tests/run_tests.py
```

## Known limits

- **The rotation rule counts user-agent strings, not crawler names.** Googlebot alone has several strings (desktop, smartphone, image), so one Googlebot address could reach three. If that's noisy for you, raise the threshold to 4 or pull the crawler name into its own field at ingest and count that.
- **Shared addresses.** A corporate proxy, carrier NAT or serverless platform can put several real clients behind one address.
- **The crawler list is a snapshot.** New AI crawlers appear every month. [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) is a good source for additions.
- **The Vite rules escape `?` on purpose.** In Sigma, `?` is a one-character wildcard; unescaped, `raw??` would match "drawing". The tests fail if an escape is removed.

## Background

The research note [Agent weather, October 2026](https://browncyber.com/research/uqscan-one-pipeline) describes the scanners these rules came from.

## License

[Detection Rule License 1.1](LICENSE.md). Keep the `author` field and a link back to this repo when you share or alert on these rules.

Corrections and false-positive reports are welcome as issues, or by email to research@browncyber.com.
