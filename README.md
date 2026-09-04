# honeypot-pipeline

An SSH/Telnet honeypot ([Cowrie](https://github.com/cowrie/cowrie)) on a free
cloud VM, plus a pipeline that turns the attack logs into a daily report:
credentials tried, commands run, malware pulled, geographic spread, and a
refreshed IP blocklist.

**[→ latest report](https://justinmreynolds93-afk.github.io/honeypot-pipeline/)** · updated daily from live sensor data

![ci](https://github.com/justinmreynolds93-afk/honeypot-pipeline/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.12-brightgreen)

## What this is

Point an SSH honeypot at the open internet and within minutes botnets are trying
`root:123456`. This repo:

1. **`sensor/`** — deploys Cowrie in Docker on an Oracle Cloud *Always Free* VM,
   moves real SSH out of the way, and captures every session as JSON.
2. **`pipeline/`** — parses `cowrie.json` into DuckDB, enriches the top source IPs
   with GeoIP + AbuseIPDB, and renders:
   - `site/index.html` — a static report (no server, published to GitHub Pages)
   - `data/blocklist.txt` — every source IP seen, ready to drop into a firewall
   - `data/credentials.csv` — every username/password pair attempted
   - `THREATS.md` — a running written summary
3. The VM regenerates all of that on a cron and `git push`es it here, so the
   commit history *is* the attack timeline.

## Architecture

```
 internet ──SSH/Telnet──▶  Cowrie (Docker, :22)  ──▶  cowrie.json
                                                          │
                              cron (daily on the VM)      ▼
                          ┌────────────────────────────────────────┐
                          │ pipeline/ingest.py   json → DuckDB      │
                          │ pipeline/enrich.py   GeoIP + AbuseIPDB  │
                          │ pipeline/report.py   DuckDB → html/md   │
                          └────────────────────────────────────────┘
                                          │ git push
                                          ▼
                     this repo  →  GitHub Pages  +  committed artifacts
```

Full write-up: [docs/architecture.md](docs/architecture.md).

## Run the pipeline without a sensor

```bash
cd pipeline
pip install -r requirements.txt
python ingest.py ../data/sample/cowrie.sample.json
python report.py
open ../site/index.html
```

The sample is ~200 sanitized events so the whole thing runs offline. CI does
exactly this on every push.

## Stand up the live sensor

You need a VM. [docs/oracle-cloud-setup.md](docs/oracle-cloud-setup.md) walks
through an Oracle Cloud Always Free instance ($0, ARM, always-on), then:

```bash
scp -r sensor/ ubuntu@<vm-ip>:~/          # after moving your real SSH to :64295
ssh -p 64295 ubuntu@<vm-ip> 'sudo bash sensor/deploy.sh'
```

Wire the daily `git push` with a deploy key — see `sensor/README.md`.

## Safety

Cowrie is a *low/medium-interaction* honeypot: it emulates a shell in a jail, it
does not run attacker commands on a real system. Downloaded payloads are stored,
not executed. Still — run it on an isolated VM with nothing else on it, and don't
reuse the VM's network for anything you care about. See `docs/architecture.md`.

## License

[MIT](LICENSE)
