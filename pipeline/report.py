#!/usr/bin/env python3
"""Render the DuckDB attack data into:

    site/index.html        static report (GitHub Pages)
    data/blocklist.txt     every source IP seen
    data/credentials.csv   every username/password pair attempted
    THREATS.md             running written summary

    python report.py
"""
from __future__ import annotations

import csv
import datetime as dt
from pathlib import Path

import duckdb
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "attacks.db"
SITE = ROOT / "site"
DATA = ROOT / "data"
TEMPLATES = Path(__file__).with_name("templates")


def q(con, sql: str) -> list[tuple]:
    return con.execute(sql).fetchall()


def svg_bars(rows: list[tuple], width: int = 420, unit: str = "") -> str:
    """rows: [(label, count), ...] -> a horizontal bar chart as inline SVG."""
    if not rows:
        return "<p class='muted'>no data yet</p>"
    top = max(r[1] for r in rows) or 1
    bar_h, gap = 22, 6
    h = len(rows) * (bar_h + gap)
    out = [f"<svg viewBox='0 0 {width} {h}' role='img' class='bars'>"]
    for i, (label, n) in enumerate(rows):
        y = i * (bar_h + gap)
        w = max(2, int((n / top) * (width - 170)))
        out.append(
            f"<text x='0' y='{y + 15}' class='lbl'>{_esc(str(label))[:22]}</text>"
            f"<rect x='150' y='{y}' width='{w}' height='{bar_h}' rx='3'/>"
            f"<text x='{158 + w}' y='{y + 15}' class='val'>{n}{unit}</text>"
        )
    out.append("</svg>")
    return "".join(out)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> int:
    if not DB.exists():
        raise SystemExit(f"{DB} not found — run ingest.py first")
    con = duckdb.connect(str(DB), read_only=True)

    totals = {
        "sessions": q(con, "select count(*) from sessions")[0][0],
        "ips": q(con, "select count(distinct src_ip) from sessions")[0][0],
        "logins": q(con, "select count(*) from logins")[0][0],
        "commands": q(con, "select count(*) from commands")[0][0],
        "downloads": q(con, "select count(*) from downloads")[0][0],
        "successful_logins": q(
            con, "select count(*) from logins where success"
        )[0][0],
    }
    span = q(
        con,
        "select min(start_ts)::date, max(coalesce(end_ts, start_ts))::date from sessions",
    )[0]

    top_ips = q(
        con,
        """
        select s.src_ip || ' (' || coalesce(i.country_code, '??') || ')' as label,
               count(*) as sessions
        from sessions s left join ip_intel i using (src_ip)
        where s.src_ip is not null
        group by 1 order by 2 desc limit 15
        """,
    )
    top_users = q(
        con,
        "select username, count(*) c from logins where username is not null "
        "group by 1 order by 2 desc limit 12",
    )
    top_passwords = q(
        con,
        "select password, count(*) c from logins where password is not null "
        "group by 1 order by 2 desc limit 12",
    )
    top_combos = q(
        con,
        "select username || ' / ' || password as combo, count(*) c from logins "
        "where username is not null group by 1 order by 2 desc limit 12",
    )
    top_commands = q(
        con,
        "select command, count(*) c from commands where command is not null "
        "group by 1 order by 2 desc limit 15",
    )
    countries = q(
        con,
        """
        select coalesce(i.country, 'unknown') country, count(distinct s.src_ip) ips
        from sessions s left join ip_intel i using (src_ip)
        group by 1 order by 2 desc limit 12
        """,
    )
    dl = q(
        con,
        "select url, shasum, count(*) c from downloads group by 1, 2 order by 3 desc limit 20",
    )
    clients = q(
        con,
        "select coalesce(client_version,'-') v, count(*) c from sessions "
        "group by 1 order by 2 desc limit 10",
    )

    # ---- artifacts -------------------------------------------------------
    DATA.mkdir(exist_ok=True)
    ips = [r[0] for r in q(con, "select distinct src_ip from sessions where src_ip is not null order by 1")]
    (DATA / "blocklist.txt").write_text(
        "# honeypot-pipeline - source IPs seen through "
        f"{span[1]}\n" + "\n".join(ips) + "\n",
        encoding="utf-8",
    )
    with open(DATA / "credentials.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "password", "attempts", "ever_accepted"])
        for u, p, c, ok in q(
            con,
            """
            select username, password, count(*),
                   bool_or(success)
            from logins where username is not null
            group by 1, 2 order by 3 desc
            """,
        ):
            w.writerow([u, p, c, ok])

    # ---- HTML -----------------------------------------------------------
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["bars"] = svg_bars
    SITE.mkdir(exist_ok=True)
    html = env.get_template("index.html.j2").render(
        generated=dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        span=span,
        totals=totals,
        top_ips=top_ips,
        top_users=top_users,
        top_passwords=top_passwords,
        top_combos=top_combos,
        top_commands=top_commands,
        countries=countries,
        downloads=dl,
        clients=clients,
    )
    (SITE / "index.html").write_text(html, encoding="utf-8")

    # ---- THREATS.md ---------------------------------------------------
    md = [
        "# Threat summary",
        "",
        f"_Auto-generated {dt.datetime.now(dt.UTC):%Y-%m-%d} from {span[0]} to {span[1]}._",
        "",
        f"- **{totals['sessions']:,}** sessions from **{totals['ips']:,}** distinct IPs",
        f"- **{totals['logins']:,}** login attempts, **{totals['successful_logins']:,}** landed on an accepted credential",
        f"- **{totals['commands']:,}** shell commands, **{totals['downloads']:,}** payload downloads",
        "",
        "## Most-tried credentials",
        "",
        "| username / password | attempts |",
        "|---|---|",
        *[f"| `{c}` | {n} |" for c, n in top_combos[:10]],
        "",
        "## Most-run commands",
        "",
        *[f"- `{_esc(cmd)[:120]}` ({n})" for cmd, n in top_commands[:10]],
        "",
        "## Payloads pulled",
        "",
        *(
            [f"- `{url}` — `{sha}` ({n})" for url, sha, n in dl[:10]]
            or ["_none yet_"]
        ),
        "",
    ]
    (ROOT / "THREATS.md").write_text("\n".join(md), encoding="utf-8")

    con.close()
    print(f"wrote site/index.html, data/blocklist.txt ({len(ips)} ips), "
          f"data/credentials.csv, THREATS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
