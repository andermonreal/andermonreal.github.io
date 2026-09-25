# frozen_string_literal: true

require 'set'

# Arsenal (rendered by _layouts/arsenal.html at /arsenal/).
#
# Three organised views a visitor (or a recruiter) can scan in seconds:
#   * Tools      — every tool used, read from each writeup's "## Tools Used"
#                  table (not the tags), unified across spellings and grouped
#                  by what it's for.
#   * Techniques — the technique tags, bucketed into domains (web, Active
#                  Directory, privilege escalation, …); tool tags are left out
#                  since tools have their own section.
#   * Platforms  — the software/stack tags.
# Each item shows how many machines it appears on. It stays in sync with the
# writeups automatically; only the grouping rules below are curated.
# Sets `site.data['arsenal']` for the layout.
module Arsenal
  # The tool catalog: category => { canonical name => [aliases, lowercased] }.
  # The "## Tools Used" tables are matched against this; add an alias here when
  # a writeup names a tool a new way. Order is the display order.
  CATALOG = {
    'Recon & scanning' => {
      'nmap' => %w[nmap], 'gobuster' => %w[gobuster], 'ffuf' => %w[ffuf],
      'wfuzz' => %w[wfuzz], 'feroxbuster' => %w[feroxbuster], 'wpscan' => %w[wpscan],
      'whatweb' => %w[whatweb], 'Wappalyzer' => %w[wappalyzer], 'nikto' => %w[nikto],
      'arp-scan' => %w[arp-scan], 'netdiscover' => %w[netdiscover], 'ping' => %w[ping],
      'ss' => %w[ss], 'tcpdump' => %w[tcpdump], 'Wireshark' => %w[wireshark]
    },
    'Web & HTTP' => {
      'Burp Suite' => ['burp suite', 'burpsuite', 'burp'], 'curl' => %w[curl], 'wget' => %w[wget],
      'Browser DevTools' => ['browser devtools', 'browser', 'web browser', 'browser + devtools', 'devtools'],
      'jwt.io' => ['jwt.io'], 'wscat' => %w[wscat], 'websocat' => %w[websocat], 'websocket' => %w[websocket]
    },
    'Passwords & hashes' => {
      'hashcat' => %w[hashcat], 'john' => ['john', 'john the ripper'], 'pdf2john' => %w[pdf2john],
      'hashid' => %w[hashid], 'passlib' => %w[passlib]
    },
    'Active Directory' => {
      'BloodHound' => ['bloodhound', 'bloodhound (legacy)', 'bloodhound-python'],
      'Impacket' => ['impacket', 'impacket psexec', 'impacket ticketconverter'],
      'evil-winrm' => %w[evil-winrm], 'Rubeus' => %w[rubeus], 'Powermad' => %w[powermad],
      'PowerView' => %w[powerview powersploit], 'crackmapexec' => %w[crackmapexec],
      'netexec' => %w[netexec nxc], 'smbclient' => %w[smbclient], 'smbmap' => %w[smbmap],
      'ldapsearch' => %w[ldapsearch]
    },
    'Shells & transfer' => {
      'netcat' => ['netcat', 'nc', 'nc.exe'], 'socat' => %w[socat], 'rlwrap' => %w[rlwrap],
      'ssh' => %w[ssh], 'ssh-keygen' => %w[ssh-keygen], 'xfreerdp' => %w[xfreerdp],
      'telnet' => %w[telnet], 'ftp' => %w[ftp], 'certutil' => %w[certutil],
      'Invoke-WebRequest' => ['invoke-webrequest', 'iwr']
    },
    'Reversing & analysis' => {
      'strings' => %w[strings], 'ILSpy' => %w[ilspy], 'jd-gui' => %w[jd-gui], 'jadx' => %w[jadx],
      'Ghidra' => %w[ghidra], 'dnSpy' => %w[dnspy]
    },
    'Mobile' => {
      'adb' => %w[adb], 'apktool' => %w[apktool], 'apksigner' => %w[apksigner], 'zipalign' => %w[zipalign],
      'keytool' => %w[keytool], 'Frida' => %w[frida], 'MobSF' => %w[mobsf], 'Genymotion' => %w[genymotion],
      'pidcat' => %w[pidcat], 'android-backup-extractor' => ['android-backup-extractor', 'abe']
    },
    'Databases' => {
      'mysql' => ['mysql', 'mariadb client', 'mariadb'], 'psql' => ['psql', 'postgresql client'],
      'sqlite3' => %w[sqlite3]
    },
    'Enumeration' => {
      'linPEAS' => %w[linpeas], 'winPEAS' => %w[winpeas], 'pspy' => %w[pspy], 'getcap' => %w[getcap]
    },
    'Scripting & dev' => {
      'Python' => ['python', 'python 3', 'python3', 'http.server', 'jwcrypto', 'requests', 'pwncat'],
      'pwntools' => %w[pwntools], 'pycryptodome' => %w[pycryptodome], 'gcc' => %w[gcc],
      'make' => %w[make], 'git' => %w[git], 'Bash' => %w[bash], 'asyncua' => %w[asyncua], 'PHP' => %w[php]
    },
    'Frameworks' => {
      'Metasploit' => ['metasploit', 'metasploit framework', 'msfconsole']
    },
    'System & misc' => {
      'su' => %w[su], 'sudo' => %w[sudo], 'find' => %w[find], 'ln' => %w[ln],
      'tar' => %w[tar tarfile], 'dpkg' => %w[dpkg], 'systemctl' => %w[systemctl],
      'systemd-run' => %w[systemd-run], 'newgrp' => %w[newgrp], 'script' => %w[script],
      'base64' => %w[base64], '7z' => %w[7z], 'zip' => %w[zip], 'busybox' => %w[busybox],
      'rclone' => %w[rclone], 'rdiff-backup' => %w[rdiff-backup], 'incron' => %w[incron],
      'mount' => %w[mount showmount], 'JupyterLab' => %w[jupyterlab jupyter],
      'docker' => %w[docker], 'echo' => %w[echo]
    }
  }.freeze

  TOOL_ORDER = CATALOG.keys.freeze

  # "## Tools Used" rows that are not really tools.
  TOOL_EXCLUDE = [/^cve-/i, /\bpoc\b/i, /\.sh\b/i, /\(custom\)/i, /privesc\.py/i, /^exploit-/i].freeze

  # alias => [canonical, category]; and every alias as a slug, so the technique
  # buckets can drop tags that are really tools.
  TOOL_LOOKUP = {}
  TOOL_ALIAS_SLUGS = []
  CATALOG.each do |cat, tools|
    tools.each do |canon, aliases|
      aliases.each do |a|
        TOOL_LOOKUP[a] = [canon, cat]
        TOOL_ALIAS_SLUGS << a.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
      end
      TOOL_ALIAS_SLUGS << canon.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
    end
  end
  TOOL_LOOKUP.freeze
  TOOL_ALIAS_SLUGS.uniq!
  TOOL_ALIAS_SLUGS.freeze

  # For a tool the catalog doesn't know yet, guess its category from its
  # description column (the second cell of the Tools Used row), so a brand-new
  # tool in a new writeup lands somewhere sensible on its own. First match wins;
  # nothing matches → the "Other" card (it still shows, just uncategorised).
  INFER = [
    ['Active Directory', /kerberos|ldap|\bsmb\b|domain controller|active directory|bloodhound|\bntlm\b|\bticket|impacket|winrm/],
    ['Mobile', /android|\bapk\b|\bios\b|mobile|frida|smali|dalvik/],
    ['Databases', /\bsql\b|database|postgres|mysql|mariadb|sqlite|mongo/],
    ['Passwords & hashes', /crack|hashcat|\bhash(es|ing)?\b|password|wordlist|rainbow/],
    ['Reversing & analysis', /decompil|disassembl|revers|debugger|\bbinary\b|packet capture|pcap|traffic|ghidra|ida\b/],
    ['Web & HTTP', /\bhttp\b|web app|proxy|intercept|\bapi\b|browser|cookie|\bjwt\b|request/],
    ['Recon & scanning', /scan|enumerat|fingerprint|discovery|\brecon|subdomain|vhost|brute-forc|fuzz|\bport/],
    ['Shells & transfer', /reverse shell|listener|\bshell\b|transfer|upload|download|tunnel|pivot|\brdp\b|exfiltrat/],
    ['Scripting & dev', /compil|\bscript|library|framework|exploit development|payload/]
  ].freeze

  # Technique domains, in order. A tag lands in the first domain one of whose
  # keywords is a substring of it; anything left over falls into "Other".
  DOMAINS = [
    ['Web exploitation',
     %w[rce sqli sql lfi traversal ssrf ssti upload xmlrpc deserial idor
        mass-assignment mass\ assignment csrf gadget session\ file php\ filter
        wordpress cms crm tinymce laravel nextjs next.js react rsc jinja
        injection xxe api\ enum self-registration webview clipboard
        cleartext-http user-enumeration]],
    ['Active Directory & Windows',
     %w[active-directory domain-controller kerberos s4u delegation genericall
        machine\ account machineaccountquota ldap smb samba rdp uac ntlm
        certificate-dialog lolbins powershell certutil invoke-webrequest]],
    ['Privilege escalation',
     %w[suid sudo gtfobins path\ hijack path\ hijacking capabilit kernel
        overlayfs fuse tar\ wildcard buffer\ overflow gets systemd execstartpre
        incron newgrp wildcard nfs pth addsitedir setuid lpe privilege
        race toctou symlink]],
    ['Containers & cloud',
     %w[docker container kubernetes kubelet rbac service\ account nodes\ proxy
        snap-confine apparmor pt_interp]],
    ['Credential access & cracking',
     %w[hash bcrypt sha1 md5 aes password credential cleartext xor reversible
        cracking libsodium pdf\ crack pdf2john default\ credentials
        hardcoded key-disclosure]],
    ['Recon & disclosure',
     %w[enumeration subdomain vhost osint disclosure information sensitive
        git\ history git\ tree leak secret fuzzing scanning anonymous\ ftp ftp]],
    ['Post-exploitation & pivoting',
     %w[reverse\ shell persistence port\ forward tunnel pivot authorized_keys
        socket scm_rights file\ descriptor systemd-run systemd\ timer]],
    ['Cryptography & reversing',
     %w[cipher crypto reversing reverse\ engineering ilspy strings\ binary
        dotnet pickle base64 rot13 deobfuscation packer]],
    ['Platforms & software',
     %w[nginx apache gitea gogs nodejs node.js mariadb postgres sqlite jupyter
        flowise mlflow langflow craft spring yii django roundcube freepbx
        zoneminder motioneye olivetin glpi limesurvey openstamanager consul
        prometheus marimo packagekit krayin arcane nifi iis php ruby\ on\ rails
        openam forgerock jato jwt sso pytorch pdfminer esm-sh jetdirect pjl
        lpd opc\ ua ics plc scada wing tomcat jetty]]
  ].freeze

  NON_TAGS = %w[linux windows android cve mobile].freeze

  # Spanish labels for the category names (for the /es/ page).
  ES = {
    'Recon & scanning' => 'Reconocimiento', 'Web' => 'Web', 'Web & HTTP' => 'Web y HTTP',
    'Passwords & hashes' => 'Contraseñas y hashes', 'Reversing & analysis' => 'Reversing y análisis',
    'Databases' => 'Bases de datos', 'Scripting & dev' => 'Scripting y desarrollo',
    'System & misc' => 'Sistema y varios',
    'Password attacks' => 'Ataques a contraseñas', 'Active Directory' => 'Active Directory',
    'Enumeration' => 'Enumeración', 'Shells & transfer' => 'Shells y transferencia',
    'Frameworks' => 'Frameworks', 'Mobile' => 'Móvil',
    'Web exploitation' => 'Explotación web',
    'Active Directory & Windows' => 'Active Directory y Windows',
    'Privilege escalation' => 'Escalada de privilegios',
    'Containers & cloud' => 'Contenedores y cloud',
    'Credential access & cracking' => 'Acceso a credenciales',
    'Recon & disclosure' => 'Reconocimiento y fugas',
    'Post-exploitation & pivoting' => 'Post-explotación y pivoting',
    'Cryptography & reversing' => 'Criptografía y reversing',
    'Platforms & software' => 'Plataformas y software', 'Other' => 'Otras'
  }.freeze

  # Font Awesome icon per category (identity is carried by icon + label, never
  # by colour alone).
  ICONS = {
    'Recon & scanning' => 'fa-satellite-dish', 'Web' => 'fa-globe', 'Web & HTTP' => 'fa-globe',
    'Passwords & hashes' => 'fa-key', 'Reversing & analysis' => 'fa-microchip',
    'Databases' => 'fa-database', 'Scripting & dev' => 'fa-code', 'System & misc' => 'fa-screwdriver-wrench',
    'Password attacks' => 'fa-key', 'Active Directory' => 'fa-sitemap',
    'Enumeration' => 'fa-list-check', 'Shells & transfer' => 'fa-terminal',
    'Frameworks' => 'fa-cubes', 'Mobile' => 'fa-mobile-screen',
    'Web exploitation' => 'fa-globe', 'Active Directory & Windows' => 'fa-sitemap',
    'Privilege escalation' => 'fa-angles-up', 'Containers & cloud' => 'fa-cloud',
    'Credential access & cracking' => 'fa-key', 'Recon & disclosure' => 'fa-magnifying-glass',
    'Post-exploitation & pivoting' => 'fa-route', 'Cryptography & reversing' => 'fa-microchip',
    'Platforms & software' => 'fa-server', 'Other' => 'fa-ellipsis'
  }.freeze

  PLATFORMS = 'Platforms & software'

  # How many chips a card shows before folding the rest behind "+N more".
  VISIBLE_MIN = 8

  module_function

  def domain_for(tag)
    DOMAINS.each do |name, keys|
      return name if keys.any? { |k| tag.include?(k) }
    end
    'Other'
  end

  # For a tool the catalog doesn't know yet, guess its category from its
  # description column so a brand-new tool lands somewhere sensible on its own.
  def infer_category(description)
    d = description.to_s.downcase
    INFER.each { |name, re| return name if d =~ re }
    'Other'
  end

  # A "## Tools Used" cell -> the tool tokens in it, in their ORIGINAL case (so
  # an unknown tool keeps its name). Parentheticals are dropped (clarifications
  # like "netcat (nc)"), and "a / b", "a + b" split into two.
  def tool_tokens(cell)
    clean = cell.gsub(/[*`]/, '').gsub(/\(.*?\)/, ' ').strip
    return [] if TOOL_EXCLUDE.any? { |re| clean =~ re }

    clean.split(%r{\s*[/+]\s*}).map { |t| t.strip.gsub(/\s+/, ' ') }.reject(&:empty?)
  end

  # A token -> [canonical, category], by exact alias or the longest alias it
  # begins/ends with (so "impacket psexec" -> Impacket). Case-insensitive.
  def match_tool(token)
    t = token.downcase
    return TOOL_LOOKUP[t] if TOOL_LOOKUP.key?(t)

    hit = TOOL_LOOKUP.keys
                     .select { |a| t == a || t.start_with?("#{a} ") || t.end_with?(" #{a}") }
                     .max_by(&:length)
    hit ? TOOL_LOOKUP[hit] : nil
  end

  # Tools from each writeup's "## Tools Used" table: canonical name => machines.
  # Always read the ENGLISH post files on disk (not `site.posts`, which is one
  # language per build and whose ES tables translate some tool names), so both
  # the /en and /es pages show the same tools and counts.
  def tools_from(site)
    counts = Hash.new(0)
    cat_of = {}

    Dir.glob(File.join(site.source, '_posts', 'en', '*.md')).sort.each do |path|
      text = File.read(path, encoding: 'utf-8')
      next if text =~ /^hidden:\s*true\s*$/

      table = text[/^##\s+Tools Used\s*\n(.*?)(?=^##\s|\z)/m, 1]
      next unless table

      seen = {}
      rows = table.lines.select { |l| l.strip.start_with?('|') }
      rows.drop(2).each do |row| # header + separator
        parts = row.strip.sub(/^\|/, '').split('|')
        cell = parts[0].to_s.strip
        desc = parts[1].to_s
        tool_tokens(cell).each do |token|
          hit = match_tool(token)
          # Known tool → catalog category; unknown → guess from its description.
          canon, cat = hit || [token, infer_category(desc)]
          next if seen[canon]

          seen[canon] = true
          counts[canon] += 1
          cat_of[canon] = cat
        end
      end
    end

    [counts, cat_of]
  end

  # Frequent items (on 2+ machines) always show; one-offs top the card up to
  # VISIBLE_MIN, and the remainder is folded away.
  def split(items)
    frequent = items.select { |i| i['count'] > 1 }
    once = items.reject { |i| i['count'] > 1 }
    room = [VISIBLE_MIN - frequent.size, 0].max
    [frequent + once.first(room), once.drop(room)]
  end

  def group(name, items, extra = {})
    visible, rest = split(items)
    {
      'category' => name, 'category_es' => ES[name] || name,
      'icon' => ICONS[name] || 'fa-circle', 'anchor' => Jekyll::Utils.slugify(name),
      'items' => items, 'visible' => visible, 'rest' => rest, 'size' => items.size
    }.merge(extra)
  end

  def build(site)
    posts = site.posts.docs.reject { |p| p.data['hidden'] }
    total = posts.size
    existing_tags = site.tags.keys.map { |t| Jekyll::Utils.slugify(t.to_s) }.to_set

    # Technique / platform tags: skip CVEs, the OS tags and anything that is
    # really a tool (it lives in the Tools section instead).
    counts = Hash.new(0)
    post_tags = posts.map do |post|
      tags = post.data['tags'].to_a.map { |t| t.to_s.strip.downcase }.uniq.reject do |tag|
        tag.empty? || tag.start_with?('cve-') || NON_TAGS.include?(tag) ||
          TOOL_ALIAS_SLUGS.include?(Jekyll::Utils.slugify(tag))
      end
      tags.each { |tag| counts[tag] += 1 }
      tags
    end

    tech_buckets = Hash.new { |h, k| h[k] = [] }
    counts.each do |tag, n|
      slug = Jekyll::Utils.slugify(tag)
      item = { 'tag' => tag, 'slug' => slug, 'count' => n, 'url' => existing_tags.include?(slug) }
      tech_buckets[domain_for(tag)] << item
    end

    by_count = ->(items) { items.sort_by { |i| [-i['count'], i['tag']] } }

    # Machines that touch each technique domain at least once.
    coverage = Hash.new(0)
    post_tags.each do |tags|
      tags.map { |t| domain_for(t) }.uniq.each { |d| coverage[d] += 1 }
    end

    # Tools, read from the "## Tools Used" tables.
    tool_counts, tool_cat = tools_from(site)
    tool_buckets = Hash.new { |h, k| h[k] = [] }
    tool_counts.each do |name, n|
      slug = Jekyll::Utils.slugify(name)
      tool_buckets[tool_cat[name]] << { 'tag' => name, 'slug' => slug, 'count' => n, 'url' => existing_tags.include?(slug) }
    end

    tools = (TOOL_ORDER + ['Other']).filter_map do |name|
      items = tool_buckets[name]
      group(name, by_count.call(items)) unless items.empty?
    end

    # Technique domains, most-covered first; "Other" always last.
    names = (DOMAINS.map(&:first) - [PLATFORMS]).select { |n| tech_buckets.key?(n) }
    names = names.sort_by { |n| [-coverage[n], -tech_buckets[n].size] }
    names << 'Other' if tech_buckets.key?('Other')
    domains = names.map do |name|
      machines = coverage[name]
      share = total.positive? ? (machines * 100.0 / total).round(1) : 0
      group(name, by_count.call(tech_buckets[name]), 'machines' => machines, 'share' => share)
    end

    platforms = tech_buckets.key?(PLATFORMS) ? group(PLATFORMS, by_count.call(tech_buckets[PLATFORMS])) : nil

    {
      'tools' => tools,
      'domains' => domains,
      'platforms' => platforms,
      'machine_total' => total,
      'tool_total' => tool_buckets.values.sum(&:size),
      'tech_total' => domains.sum { |d| d['size'] },
      'platform_total' => platforms ? platforms['size'] : 0,
      'domain_total' => domains.count { |d| d['category'] != 'Other' }
    }
  end
end

Jekyll::Hooks.register :site, :pre_render do |site|
  site.data['arsenal'] = Arsenal.build(site)
end
