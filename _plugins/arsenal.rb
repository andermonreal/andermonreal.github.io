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

  module_function

  def domain_for(tag)
    DOMAINS.each do |name, keys|
      return name if keys.any? { |k| tag.include?(k) }
    end
    'Other'
  end

  def build(site)
    counts = Hash.new(0)
    site.posts.docs.each do |post|
      next if post.data['hidden']

      post.data['tags'].to_a.map { |t| t.to_s.strip.downcase }.uniq.each do |tag|
        next if tag.empty? || tag.start_with?('cve-') || NON_TAGS.include?(tag)

        counts[tag] += 1
      end
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

    tools = TOOL_ORDER.filter_map do |name|
      items = tool_buckets[name]
      { 'category' => name, 'category_es' => ES[name] || name, 'items' => by_count.call(items) } unless items.empty?
    end

    domain_order = DOMAINS.map(&:first) + ['Other']
    techniques = domain_order.filter_map do |name|
      items = tech_buckets[name]
      { 'category' => name, 'category_es' => ES[name] || name, 'items' => by_count.call(items) } unless items.empty?
    end

    {
      'tools' => tools,
      'techniques' => techniques,
      'tool_total' => tool_buckets.values.sum(&:size),
      'tech_total' => tech_buckets.values.sum(&:size)
    }
  end
end

Jekyll::Hooks.register :site, :pre_render do |site|
  site.data['arsenal'] = Arsenal.build(site)
end
