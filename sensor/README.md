# sensor/

Everything that runs on the honeypot VM.

| file | what |
|---|---|
| `deploy.sh` | install Docker, run the `cowrie/cowrie` image on `:22`/`:23`, systemd restart |
| `cowrie.cfg` | Cowrie config — JSON output, plausible hostname / SSH banner |
| `userdb.txt` | which credentials Cowrie "accepts" (so you capture post-login activity) |
| `install-cron.sh` | daily job: ingest → enrich → report → `git commit && git push` |

## Order of operations

1. Create the VM and **move your real SSH to port 64295** — [../docs/oracle-cloud-setup.md](../docs/oracle-cloud-setup.md).
2. `scp -P 64295 -r sensor/ ubuntu@<ip>:~/`
3. `ssh -p 64295 ubuntu@<ip> 'sudo bash sensor/deploy.sh'`
4. Add a **deploy key** (write access) to the repo, put the private key at
   `/root/.ssh/honeypot_deploy` on the VM.
5. `sudo bash sensor/install-cron.sh` then `sudo honeypot-report` once to seed.
6. Enable **GitHub Pages** for the repo (Settings → Pages → deploy from `main` / `/site`).

## Health check

```bash
docker logs --tail 30 cowrie
tail -f /opt/cowrie/log/cowrie.json          # events as they land
cat /var/log/honeypot-report.log             # last cron run
```

## Notes

- Cowrie is low/medium-interaction: emulated busybox shell in a jail, attacker
  commands are **not** run on the host. Downloaded files are saved to
  `/opt/cowrie/downloads/` (sha256-named), not executed.
- The VM should do nothing else. Treat its IP as burned.
- `cowrie.json` rotates; `install-cron.sh` ingests the current file plus any
  `cowrie.json.YYYY-MM-DD` archives. `ingest.py` is idempotent so overlap is fine.
