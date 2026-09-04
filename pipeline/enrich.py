#!/usr/bin/env python3
"""Fill ip_intel for every source IP: country / ASN / org via ip-api.com (free,
no key, batched), plus an AbuseIPDB confidence score if ABUSEIPDB_API_KEY is set.

    python enrich.py            # enrich IPs not seen in the last 7 days
    python enrich.py --all      # re-enrich everything
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

DB = Path(__file__).resolve().parent.parent / "data" / "attacks.db"
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")


def _post_json(url: str, payload, headers=None) -> object:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", **(headers or {})}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def _get_json(url: str, headers=None) -> object:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def geo_batch(ips: list[str]) -> dict[str, dict]:
    """ip-api.com batch: up to 100 IPs, ~15 req/min unauthenticated."""
    out: dict[str, dict] = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i : i + 100]
        fields = "status,message,query,country,countryCode,as,org,proxy"
        res = _post_json(f"http://ip-api.com/batch?fields={fields}", chunk)
        for row in res:  # type: ignore[union-attr]
            if row.get("status") == "success":
                out[row["query"]] = row
        time.sleep(4.5)
    return out


def abuse_score(ip: str) -> int | None:
    if not ABUSE_KEY:
        return None
    try:
        res = _get_json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        )
        return int(res["data"]["abuseConfidenceScore"])  # type: ignore[index]
    except Exception:
        return None


def main(argv: list[str]) -> int:
    if not DB.exists():
        raise SystemExit(f"{DB} not found — run ingest.py first")
    con = duckdb.connect(str(DB))

    if "--all" in argv:
        todo = [r[0] for r in con.execute(
            "select distinct src_ip from sessions where src_ip is not null"
        ).fetchall()]
    else:
        cutoff = datetime.now(UTC) - timedelta(days=7)
        todo = [r[0] for r in con.execute(
            """
            select distinct s.src_ip from sessions s
            left join ip_intel i using (src_ip)
            where s.src_ip is not null
              and (i.src_ip is null or i.updated_ts < ?)
            """,
            [cutoff],
        ).fetchall()]

    if not todo:
        print("nothing to enrich")
        return 0
    print(f"enriching {len(todo)} IPs")

    geo = geo_batch(todo)
    now = datetime.now(UTC)
    rows = []
    for ip in todo:
        g = geo.get(ip, {})
        rows.append((
            ip, g.get("country"), g.get("countryCode"),
            (g.get("as") or "").split(" ")[0] or None, g.get("org"),
            abuse_score(ip), bool(g.get("proxy")), now,
        ))
    con.executemany(
        """
        insert into ip_intel values (?,?,?,?,?,?,?,?)
        on conflict (src_ip) do update set
          country=excluded.country, country_code=excluded.country_code,
          asn=excluded.asn, org=excluded.org, abuse_score=excluded.abuse_score,
          is_tor=excluded.is_tor, updated_ts=excluded.updated_ts
        """,
        rows,
    )
    con.close()
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
