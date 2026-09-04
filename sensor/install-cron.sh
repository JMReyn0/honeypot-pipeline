#!/usr/bin/env bash
# Installs the daily job: ingest new Cowrie logs, enrich, regenerate the report,
# commit and push. Run as root on the sensor VM after deploy.sh.
#
# Prereqs:
#   - a GitHub deploy key with write access is in ~/.ssh/honeypot_deploy
#   - you know the repo SSH URL
set -euo pipefail

REPO_URL="${1:-git@github.com:justinmreynolds93-afk/honeypot-pipeline.git}"
CHECKOUT=/opt/honeypot-pipeline
KEY=/root/.ssh/honeypot_deploy

[ -f "$KEY" ] || { echo "!! $KEY missing — see docs/oracle-cloud-setup.md step 6" >&2; exit 1; }

export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes"

apt-get update -qq
apt-get install -y -qq python3-venv git

if [ ! -d "$CHECKOUT/.git" ]; then
  git clone "$REPO_URL" "$CHECKOUT"
fi
python3 -m venv "$CHECKOUT/.venv"
"$CHECKOUT/.venv/bin/pip" install -q -r "$CHECKOUT/pipeline/requirements.txt"

cat > /usr/local/bin/honeypot-report <<EOF
#!/usr/bin/env bash
set -euo pipefail
export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes"
cd $CHECKOUT
git pull --ff-only
PY=$CHECKOUT/.venv/bin/python
# rotate: cowrie writes cowrie.json; copy the last 14 days of it in
cp /opt/cowrie/log/cowrie.json /tmp/cowrie.current.json
\$PY pipeline/ingest.py /tmp/cowrie.current.json /opt/cowrie/log/cowrie.json.*
\$PY pipeline/enrich.py
\$PY pipeline/report.py
git add -f data/attacks.db
git add data/blocklist.txt data/credentials.csv site/ THREATS.md
git -c user.name="honeypot-sensor" -c user.email="sensor@localhost" \
    commit -m "report \$(date -u +%F)" --allow-empty
git push
EOF
chmod +x /usr/local/bin/honeypot-report

# 05:17 UTC daily
( crontab -l 2>/dev/null | grep -v honeypot-report; echo "17 5 * * * /usr/local/bin/honeypot-report >> /var/log/honeypot-report.log 2>&1" ) | crontab -

echo "installed. run once now:  honeypot-report"
