# frozen_string_literal: true

# Arsenal & skills (rendered by _layouts/arsenal.html at /arsenal/).
#
# Turns the flat tag cloud of the writeups into two organised views a visitor
# (or a recruiter) can scan in seconds:
#   * Tools    — the named tools used, grouped by what they're for.
#   * Techniques — every other technique tag, bucketed into domains
#                  (web, Active Directory, privilege escalation, …).
# Each item shows how many machines it appears on and links to its tag page.
#
# It is all derived from the posts' own tags, so it stays in sync automatically;
# only the grouping rules below are curated (labels and keywords, no content).
# Sets `site.data['arsenal']` for the layout.
module Arsenal
  # Named tools → the bucket they belong to. Only these slugs show under "Tools".
  TOOLS = {
    'nmap' => 'Recon & scanning', 'gobuster' => 'Recon & scanning',
    'wpscan' => 'Recon & scanning', 'wappalyzer' => 'Recon & scanning',
    'wireshark' => 'Recon & scanning', 'ffuf' => 'Recon & scanning',
    'burp-suite' => 'Web', 'burp suite' => 'Web',
    'hashcat' => 'Password attacks', 'john the ripper' => 'Password attacks',
    'pdf2john' => 'Password attacks',
    'bloodhound' => 'Active Directory', 'impacket' => 'Active Directory',
    'winpeas' => 'Enumeration',
    'frida' => 'Mobile', 'mobsf' => 'Mobile', 'drozer' => 'Mobile',
    'apktool' => 'Mobile', 'adb' => 'Mobile',
    'netcat' => 'Shells & transfer', 'nc-exe' => 'Shells & transfer',
    'rlwrap' => 'Shells & transfer', 'rclone' => 'Shells & transfer',
    'xfreerdp' => 'Shells & transfer',
    'metasploit' => 'Frameworks', 'msfconsole' => 'Frameworks',
    'meterpreter' => 'Frameworks'
  }.freeze

  # The order tool buckets are shown in.
  TOOL_ORDER = ['Recon & scanning', 'Web', 'Password attacks', 'Active Directory',
                'Enumeration', 'Shells & transfer', 'Frameworks', 'Mobile'].freeze

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
    'Recon & scanning' => 'Reconocimiento', 'Web' => 'Web',
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
    'Recon & scanning' => 'fa-satellite-dish', 'Web' => 'fa-globe',
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

    counts = Hash.new(0)
    post_tags = posts.map do |post|
      tags = post.data['tags'].to_a.map { |t| t.to_s.strip.downcase }.uniq.reject do |tag|
        tag.empty? || tag.start_with?('cve-') || NON_TAGS.include?(tag)
      end
      tags.each { |tag| counts[tag] += 1 }
      tags
    end

    tool_buckets = Hash.new { |h, k| h[k] = [] }
    tech_buckets = Hash.new { |h, k| h[k] = [] }

    counts.each do |tag, n|
      item = { 'tag' => tag, 'slug' => Jekyll::Utils.slugify(tag), 'count' => n }
      if TOOLS.key?(tag)
        tool_buckets[TOOLS[tag]] << item
      else
        tech_buckets[domain_for(tag)] << item
      end
    end

    by_count = ->(items) { items.sort_by { |i| [-i['count'], i['tag']] } }

    # Machines that touch each technique domain at least once.
    coverage = Hash.new(0)
    post_tags.each do |tags|
      tags.reject { |t| TOOLS.key?(t) }.map { |t| domain_for(t) }.uniq.each { |d| coverage[d] += 1 }
    end

    tools = TOOL_ORDER.filter_map do |name|
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
