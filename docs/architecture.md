# Architecture

## Goal

Run an internet-facing SSH/Telnet sensor for near-zero cost, and turn its logs
into something a person actually reads — a daily report, a blocklist, a written
threat summary — with the whole thing reproducible from this repo.

## Pieces

```
                       ┌───────────────────────────────┐
   internet ──:22/:23──▶ Cowrie (Docker)               │  Oracle Cloud
                       │  emulated shell, JSON output   │  Always Free VM
                       └───────────────┬───────────────┘  (Ampere A1, 1 OCPU)
                                       │ /opt/cowrie/log/cowrie.json
                                       ▼
                       ┌───────────────────────────────┐
   cron 05:17 UTC ─────▶ pipeline/ (Python venv)        │
                       │  ingest.py   json  → DuckDB    │
                       │  enrich.py   ip-api + AbuseIPDB│
                       │  report.py   DuckDB → outputs  │
                       └───────────────┬───────────────┘
                                       │ git commit && git push (deploy key)
                                       ▼
                 ┌───────────────────────────────────────────┐
                 │ this repo                                  │
                 │  site/index.html   → GitHub Pages          │
                 │  data/blocklist.txt, data/credentials.csv  │
                 │  THREATS.md                                │
                 │  data/attacks.db  (DuckDB, committed)      │
                 └───────────────────────────────────────────┘
```

## Why these choices

- **Cowrie, not a real box.** Low/medium-interaction: it emulates a BusyBox shell
  in a jail. Attacker commands never execute on the host; downloads are stored,
  not run. That makes an always-on public sensor safe to operate solo.
- **Oracle Always Free.** A genuinely free, always-on VM. AWS/GCP free tiers
  expire or bill; a $5 VPS also works and `deploy.sh` is host-agnostic.
- **DuckDB, committed to the repo.** Single file, no server, fast analytics, and
  small enough (a few MB) to version. Anyone can `duckdb data/attacks.db` and
  query the raw history. `ingest.py` is idempotent so re-running over rotated
  logs never double-counts.
- **Static report + git push, not a hosted dashboard.** Nothing to keep running,
  nothing to pay for, and the commit history becomes the attack timeline.
- **Pipeline on the VM, CI only lints.** The VM has the data; CI just proves the
  pipeline runs (against `data/sample/`).

## Data model

`pipeline/schema.sql`. Cowrie's `eventid` stream is folded into
`sessions` (one row per connection) plus append-only `logins`, `commands`,
`downloads`, and an `ip_intel` enrichment table keyed by IP.

## Threats to the setup itself

| risk | mitigation |
|---|---|
| VM compromise via a Cowrie CVE | isolated VM, nothing else on it, its IP treated as burned; keep the image updated |
| Cowrie used as a proxy pivot | `direct-tcpip` is logged; Cowrie does not actually forward |
| Log/credential exposure in a public repo | source IPs and attempted creds are attacker data, not secrets; no real service creds exist on the VM |
| Deploy key leak | key is write-scoped to this one repo; rotate on the VM if needed |
