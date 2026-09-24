# frozen_string_literal: true

# Attack path (_includes/attack-path.html renders it, _layouts/post.html shows
# it under the machine card).
#
# Every writeup already tells its story through its section headings — a Recon
# section, an Exploitation section, then "Lateral Movement — `app` → `josh`"
# and "Privilege Escalation — `josh` → `root`". This generator reads those
# headings and turns them into a compact chain a visitor can grasp in seconds:
#
#     Recon → Initial access (CVE-…) → User josh → Root (CVE-…)
#
# The account pivots and CVE ids come straight from the post's own headings, so
# the chain is exactly as accurate as the writeup — nothing is inferred about
# how the machine works. It writes `post.data['attack_path']`; a post can
# override that array in its front matter, or set `attack_path: false` to hide
# the strip. Protected (active-machine) writeups are skipped so the strip never
# discloses a live box's route.
module AttackPath
  ARROW = /→|➜|-&gt;|->/.freeze
  CVE = /CVE-\d{4}-\d{3,7}/i.freeze
  ROOT = /\A(root|system|administrator|nt authority)/i.freeze

  # A heading line: `## H2` / `### H3` in Markdown, or a rendered <h2>/<h3>.
  # Matched one line at a time, so neither pattern runs away over the document.
  HEAD_MD = /^(\#\#\#?)[^\#]\s*(.+?)\s*$/.freeze
  HEAD_HTML = /<h([23])\b[^>]*>(.*?)<\/h\1>/i.freeze

  # Phase keywords, English and Spanish. Order matters: the more specific
  # "lateral" / "privilege" win over the generic "exploit".
  PHASES = [
    [:recon,    /recon|enumerat|reconoc|enumerac/i],
    [:root,     /privilege escalation|privesc|escalada|escalaci/i],
    [:lateral,  /lateral|pivot|movimiento/i],
    [:foothold, /exploit|explotaci|foothold|initial access|acceso inicial|web shell|reverse shell/i]
  ].freeze

  module_function

  def classify(text)
    PHASES.each { |name, re| return name if text =~ re }
    nil
  end

  def root?(account)
    account =~ ROOT
  end

  # The `code`-quoted account names on each side of an arrow, e.g.
  # "… — `www-data` → `josh` (…)" → ["www-data", "josh"]. Only backtick-quoted
  # names count, so prose like "cracked credential →" is left out.
  def arrow_accounts(text)
    return nil unless text =~ ARROW

    left, right = text.split(ARROW, 2)
    l = left[/`([^`]+)`\s*\z/, 1] || left[/`([^`]+)`(?!.*`)/, 1]
    r = right[/\A\s*`([^`]+)`/, 1] || right[/`([^`]+)`/, 1]
    [l, r]
  end

  def headings_of(content)
    found = []
    content.each_line do |line|
      if (m = line.match(HEAD_MD))
        found << [m[1].length, m[2].strip]
      elsif (m = line.match(HEAD_HTML))
        found << [m[1].to_i, m[2].gsub(/<[^>]+>/, '').strip]
      end
    end
    found
  end

  def build(content)
    headings = headings_of(content)
    return nil if headings.empty?

    accounts = []   # ordered non-root accounts reached: [{account, cve}]
    has_recon = false
    has_exploit = false
    has_privesc = false
    foothold_cve = nil
    root_cve = nil
    root_account = nil
    phase = nil

    add = lambda do |name, cve|
      return if name.nil? || name.empty?

      if root?(name)
        root_account ||= name
        root_cve ||= cve
      elsif (last = accounts.last) && last['account'] == name
        last['cve'] ||= cve
      else
        accounts << { 'account' => name, 'cve' => cve }
      end
    end

    headings.each do |level, text|
      kind = classify(text)
      phase = kind if level == 2 && kind # a section sets the phase; ### inherits
      cve = text[CVE] && text[CVE].upcase

      has_recon ||= phase == :recon
      has_exploit ||= phase == :foothold
      has_privesc ||= phase == :root
      foothold_cve ||= cve if phase == :foothold
      root_cve ||= cve if phase == :root

      # Account pivots come only from section (`##`) headings; a `###` step
      # heading like "`melendez` → `monre`" is an internal detail, and its CVE
      # was already folded into the phase above.
      next unless level == 2

      pair = arrow_accounts(text)
      next unless pair && (pair[0] || pair[1])

      add.call(pair[0], nil)
      add.call(pair[1], cve)
    end

    root_account ||= 'root' if has_privesc
    accounts.first['cve'] ||= foothold_cve if accounts.first

    steps = []
    steps << { 'phase' => 'recon' } if has_recon

    if accounts.any?
      steps << { 'phase' => 'foothold', 'account' => accounts.first['account'], 'cve' => accounts.first['cve'] }
      accounts.drop(1).each { |c| steps << { 'phase' => 'user', 'account' => c['account'], 'cve' => c['cve'] } }
      steps << { 'phase' => 'root', 'account' => root_account, 'cve' => root_cve } if root_account
    else
      steps << { 'phase' => 'foothold', 'cve' => foothold_cve } if has_exploit
      steps << { 'phase' => 'root', 'account' => root_account, 'cve' => root_cve } if has_privesc
    end

    # Needs at least a start and an end to read as a path.
    steps.length >= 2 ? steps : nil
  end
end

Jekyll::Hooks.register :posts, :pre_render do |post|
  next if post.data.key?('attack_path') # author override (array, or false)
  next if post.data['protected']
  next if post.data['hidden']

  path = AttackPath.build(post.content)
  post.data['attack_path'] = path unless path.nil?
end
