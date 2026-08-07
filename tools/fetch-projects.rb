#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Sync the Projects page with GitHub.
#
# Fetches the configured user's public repositories and writes
# _data/projects_generated.json — the flat, ordered list the Projects page
# renders. Curation (which repos to hide/pin and custom EN/ES descriptions)
# comes from _data/projects.yml.
#
# Run locally any time to refresh:   ruby tools/fetch-projects.rb
# In CI it runs before `jekyll build` (see .github/workflows/pages-deploy.yml).
# If GITHUB_TOKEN is set (Actions provides one automatically) it is used only to
# raise the API rate limit; listing public repos works without it too.
#
# On a network/API error it prints a warning and leaves any existing generated
# file untouched, so a transient GitHub hiccup never wipes the page.

require 'json'
require 'yaml'
require 'net/http'
require 'uri'

CONFIG_PATH = File.join(__dir__, '..', '_data', 'projects.yml')
OUT_PATH    = File.join(__dir__, '..', '_data', 'projects_generated.json')

config = File.exist?(CONFIG_PATH) ? (YAML.load_file(CONFIG_PATH) || {}) : {}
user            = config['github_user'] || 'andermonreal'
exclude         = Array(config['exclude']).map(&:to_s)
include_forks   = config['include_forks'] ? true : false
exclude_archived = config.fetch('exclude_archived', true) ? true : false
order_list      = Array(config['order'] || config['featured']).map(&:to_s)
overrides       = config['overrides'] || {}

def gh_get(uri, accept)
  token = ENV['GITHUB_TOKEN']
  req = Net::HTTP::Get.new(uri)
  req['Accept'] = accept
  req['User-Agent'] = 'projects-sync-script'
  req['Authorization'] = "Bearer #{token}" if token && !token.empty?
  Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(req) }
end

# Turn a repo name into a URL slug: "Problema_del_viajante" -> "problema-del-viajante".
def slugify(name)
  name.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/\A-+|-+\z/, '')
end

# Rewrite README-relative image/link URLs to absolute GitHub URLs so they still
# work when the README is embedded on our own page.
def absolutize_readme(html, user, repo, branch)
  return html if html.nil?

  raw  = "https://raw.githubusercontent.com/#{user}/#{repo}/#{branch}/"
  blob = "https://github.com/#{user}/#{repo}/blob/#{branch}/"

  relative = lambda do |val|
    val.nil? || val.start_with?('http://', 'https://', '//', '#', 'mailto:', 'data:')
  end

  # Images -> raw.githubusercontent.com
  html = html.gsub(/(<img\b[^>]*?\bsrc=")([^"]*)(")/i) do
    pre, val, post = Regexp.last_match(1), Regexp.last_match(2), Regexp.last_match(3)
    relative.call(val) ? "#{pre}#{val}#{post}" : "#{pre}#{raw}#{val.sub(%r{\A\./}, '')}#{post}"
  end

  # Links -> github.com/.../blob (anchors and absolute links left alone)
  html = html.gsub(/(<a\b[^>]*?\bhref=")([^"]*)(")/i) do
    pre, val, post = Regexp.last_match(1), Regexp.last_match(2), Regexp.last_match(3)
    relative.call(val) ? "#{pre}#{val}#{post}" : "#{pre}#{blob}#{val.sub(%r{\A\./}, '')}#{post}"
  end

  # GitHub renders heading ids as `user-content-foo` but links to `#foo`; drop
  # the prefix so in-page anchors work on our copy.
  html.gsub('id="user-content-', 'id="')
end

def fetch_readme(user, repo, branch)
  res = gh_get(URI("https://api.github.com/repos/#{user}/#{repo}/readme"),
               'application/vnd.github.html')
  return nil unless res.code.to_i == 200

  # Net::HTTP bodies come back as ASCII-8BIT; GitHub's HTML is UTF-8.
  absolutize_readme(res.body.dup.force_encoding('UTF-8'), user, repo, branch)
rescue StandardError
  nil
end

def fetch_repos(user)
  repos = []
  page = 1

  loop do
    uri = URI("https://api.github.com/users/#{user}/repos" \
              "?per_page=100&page=#{page}&sort=updated&type=owner")
    res = gh_get(uri, 'application/vnd.github+json')
    raise "GitHub API returned #{res.code}: #{res.body.to_s[0, 200]}" unless res.code.to_i == 200

    batch = JSON.parse(res.body)
    break if batch.empty?

    repos.concat(batch)
    break if batch.size < 100

    page += 1
  end

  repos
end

begin
  repos = fetch_repos(user)
rescue StandardError => e
  warn "::warning::fetch-projects: could not sync from GitHub (#{e.message}). " \
       "Keeping the existing #{File.basename(OUT_PATH)}."
  # Leave any existing generated file in place; create an empty one if none.
  File.write(OUT_PATH, "[]\n") unless File.exist?(OUT_PATH)
  exit 0
end

# Filter out what we don't want to show.
repos.reject! { |r| r['fork'] && !include_forks }
repos.reject! { |r| r['archived'] && exclude_archived }
repos.reject! { |r| exclude.include?(r['name']) }

# Build display entries, letting per-repo overrides win over GitHub's data.
# Each entry also carries its rendered README (for its own /projects/<slug>/ page).
entries = repos.map do |r|
  ov     = overrides[r['name']] || {}
  desc   = r['description']
  readme = fetch_readme(user, r['name'], r['default_branch'])

  {
    'repo'        => r['name'],
    'slug'        => slugify(r['name']),
    'name'        => ov['name'] || r['name'],
    'url'         => ov['url'] || r['html_url'],
    'language'    => ov['language'] || r['language'],
    'desc_en'     => ov['desc_en'] || desc,
    'desc_es'     => ov['desc_es'] || ov['desc_en'] || desc,
    'stars'       => r['stargazers_count'],
    'updated'     => r['pushed_at'],
    'has_readme'  => !readme.nil?,
    'readme_html' => readme
  }
end

# Ordering: the repos listed in `order` first, in exactly that order; any repo
# not listed is appended at the end, most recently pushed first.
listed = order_list.map { |name| entries.find { |e| e['repo'] == name } }.compact
rest = (entries - listed).sort_by { |e| e['updated'].to_s }.reverse
ordered = listed + rest

File.write(OUT_PATH, JSON.pretty_generate(ordered) + "\n")
puts "fetch-projects: wrote #{ordered.size} projects to #{File.basename(OUT_PATH)}."
