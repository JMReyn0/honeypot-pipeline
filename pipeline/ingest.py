#!/usr/bin/env python3
"""Parse one or more Cowrie JSON log files into DuckDB (data/attacks.db).

Idempotent: re-running against overlapping logs will not duplicate rows.

    python ingest.py /path/to/cowrie.json [more.json ...]
    python ingest.py ../data/sample/cowrie.sample.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "attacks.db"
SCHEMA = Path(__file__).with_name("schema.sql")


def load_events(paths: list[str]):
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2

    DB.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(DB))
    con.execute(SCHEMA.read_text())

    logins, commands, downloads = [], [], []
    sess: dict[str, dict] = {}

    for e in load_events(argv):
        eid = e.get("eventid", "")
        s = e.get("session")
        ts = e.get("timestamp")
        ip = e.get("src_ip")
        if not s:
            continue
        row = sess.setdefault(s, {"session": s})

        if eid == "cowrie.session.connect":
            row.update(
                src_ip=ip,
                src_port=e.get("src_port"),
                protocol=e.get("protocol", "ssh"),
                start_ts=ts,
            )
        elif eid == "cowrie.client.version":
            row["client_version"] = e.get("version")
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            ok = eid.endswith("success")
            logins.append((ts, s, ip, e.get("username"), e.get("password"), ok))
            row["login_user"] = e.get("username")
            row["login_pass"] = e.get("password")
            row["login_success"] = row.get("login_success") or ok
        elif eid == "cowrie.command.input":
            commands.append((ts, s, ip, e.get("input")))
        elif eid == "cowrie.session.file_download":
            downloads.append(
                (ts, s, ip, e.get("url"), e.get("shasum"), e.get("outfile"))
            )
        elif eid == "cowrie.session.closed":
            row["end_ts"] = ts
            row["duration_s"] = e.get("duration")

    session_rows = [
        (
            r["session"],
            r.get("src_ip"),
            r.get("src_port"),
            r.get("protocol"),
            r.get("client_version"),
            r.get("start_ts"),
            r.get("end_ts"),
            r.get("duration_s"),
            r.get("login_user"),
            r.get("login_pass"),
            r.get("login_success", False),
        )
        for r in sess.values()
    ]

    con.execute("begin")
    _upsert_sessions(con, session_rows)
    _append_new(con, "logins", logins, key_cols=6)
    _append_new(con, "commands", commands, key_cols=4)
    _append_new(con, "downloads", downloads, key_cols=6)
    con.execute("commit")

    counts = {
        t: con.execute(f"select count(*) from {t}").fetchone()[0]
        for t in ("sessions", "logins", "commands", "downloads")
    }
    print("db:", DB)
    for t, n in counts.items():
        print(f"  {t:10} {n}")
    con.close()
    return 0


def _upsert_sessions(con, rows):
    if not rows:
        return
    con.executemany(
        """
        insert into sessions values (?,?,?,?,?,?,?,?,?,?,?)
        on conflict (session) do update set
          src_ip=excluded.src_ip, src_port=excluded.src_port,
          protocol=excluded.protocol, client_version=excluded.client_version,
          start_ts=excluded.start_ts, end_ts=excluded.end_ts,
          duration_s=excluded.duration_s, login_user=excluded.login_user,
          login_pass=excluded.login_pass, login_success=excluded.login_success
        """,
        rows,
    )


def _append_new(con, table: str, rows: list[tuple], key_cols: int):
    """Insert rows not already present (compare the full tuple)."""
    if not rows:
        return
    placeholders = ",".join(["?"] * key_cols)
    con.execute(f"create temp table _stage as select * from {table} limit 0")
    con.executemany(f"insert into _stage values ({placeholders})", rows)
    con.execute(
        f"""
        insert into {table}
        select s.* from _stage s
        anti join {table} t using ({', '.join(_colnames(con, table))})
        """
    )
    con.execute("drop table _stage")


def _colnames(con, table: str) -> list[str]:
    return [r[0] for r in con.execute(f"describe {table}").fetchall()]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
