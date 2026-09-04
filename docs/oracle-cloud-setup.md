# Oracle Cloud Always Free — honeypot VM

Oracle's Always Free tier gives you an ARM (Ampere A1) VM that stays on forever:
up to 4 OCPU / 24 GB RAM across your free instances, 200 GB block storage, 10 TB
egress/month. One small instance is plenty for Cowrie.

> Oracle asks for a credit card to verify identity. Always Free resources are not
> charged; to be certain, **do not upgrade to a paid account** and set a budget
> alert at $1.

## 1. Create the account

1. <https://www.oracle.com/cloud/free/> → *Start for free*.
2. Pick a **Home Region** close to you (can't change it later).
3. Verify email, phone, card. Wait for provisioning (a few minutes to a few hours).

## 2. Create the instance

Console → *Compute* → *Instances* → *Create instance*:

| Field | Value |
|---|---|
| Name | `honeypot` |
| Image | Canonical Ubuntu 24.04 (minimal is fine) |
| Shape | *Ampere* → `VM.Standard.A1.Flex`, **1 OCPU / 6 GB** |
| SSH keys | upload your public key (`~/.ssh/id_ed25519.pub`) |
| Networking | create a new VCN, **assign a public IPv4** |

Create. Note the **public IP**.

## 3. Open the ports

Cowrie listens on 22 (fake) and 23 (fake Telnet). Real SSH moves to 64295.

**VCN → Security List → Add Ingress Rules** (source `0.0.0.0/0`):

| Port | Why |
|---|---|
| 22 | honeypot SSH — you *want* this hit |
| 23 | honeypot Telnet |
| 64295 | your real SSH |

Remove the default rule that allows 22 to your IP only — you want 22 open to the world.

## 4. Move real SSH, then lock down

First connection is still on 22:

```bash
ssh ubuntu@<public-ip>

sudo sed -i 's/^#\?Port .*/Port 64295/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# also open 64295 in Ubuntu's own firewall if ufw is on:
sudo ufw allow 64295/tcp && sudo ufw --force enable && sudo ufw allow 22/tcp && sudo ufw allow 23/tcp
```

Reconnect on the new port and confirm before closing the first session:

```bash
ssh -p 64295 ubuntu@<public-ip>
```

## 5. Deploy Cowrie

```bash
scp -P 64295 -r sensor/ ubuntu@<public-ip>:~/
ssh -p 64295 ubuntu@<public-ip> 'sudo bash sensor/deploy.sh'
```

`deploy.sh` installs Docker, runs the `cowrie/cowrie` image with `sensor/cowrie.cfg`
mounted, redirects `:22`/`:23` to Cowrie's `2222`/`2223`, and sets a systemd unit
so it survives reboot.

## 6. Wire the daily report push

On the VM:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/honeypot_deploy -N ''
cat ~/.ssh/honeypot_deploy.pub
```

Add that as a **deploy key with write access** on this repo (Settings → Deploy
keys). Then:

```bash
sudo bash sensor/install-cron.sh   # clones this repo, installs the daily job
```

Every night the VM runs `pipeline/`, commits `site/`, `data/`, `THREATS.md`, and
pushes. GitHub Pages serves `site/`.

## Teardown

Console → Instance → *Terminate* (also delete the boot volume). Nothing to pay.
