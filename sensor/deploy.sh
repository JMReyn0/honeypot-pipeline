#!/usr/bin/env bash
# Deploy Cowrie in Docker on this VM. Run as root, AFTER you have moved your real
# SSH to port 64295 (see docs/oracle-cloud-setup.md).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== checking real SSH is not on :22"
if ss -tlnp | grep -q ':22 '; then
  echo "!! something is still listening on :22 — move sshd to :64295 first" >&2
  exit 1
fi

echo "== installing Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

echo "== preparing Cowrie data dirs"
install -d -o 1000 -g 1000 /opt/cowrie/{data,downloads,log}
cp "$HERE/cowrie.cfg"  /opt/cowrie/cowrie.cfg
cp "$HERE/userdb.txt"  /opt/cowrie/userdb.txt

echo "== (re)creating the container"
docker rm -f cowrie 2>/dev/null || true
docker run -d --name cowrie --restart unless-stopped \
  -p 22:2222 -p 23:2223 \
  -v /opt/cowrie/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro \
  -v /opt/cowrie/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro \
  -v /opt/cowrie/log:/cowrie/cowrie-git/var/log/cowrie \
  -v /opt/cowrie/downloads:/cowrie/cowrie-git/var/lib/cowrie/downloads \
  cowrie/cowrie:latest

echo "== firewall"
if command -v ufw >/dev/null; then
  ufw allow 22/tcp; ufw allow 23/tcp; ufw allow 64295/tcp
fi

sleep 3
docker logs --tail 15 cowrie
echo
echo "cowrie is up. JSON log: /opt/cowrie/log/cowrie.json"
echo "next: sudo bash $HERE/install-cron.sh   (daily report + git push)"
