# frozen_string_literal: true

# Sync each writeup's tags with the tools it actually used.
#
# The Arsenal counts tools from every post's "## Tools Used" table, but the
# tags were never kept in step — so a tool page (e.g. /tags/burp-suite/) and a
# tag search listed far fewer machines than really used the tool. This script
# reads each post's Tools Used table (the ENGLISH file, the source of truth —
# the ES tables translate some names), canonicalises every tool with the SAME
# catalog the Arsenal uses (_plugins/arsenal.rb), and makes sure each tool is
# present as a tag in BOTH language files. Existing tags are kept and their
# order preserved; only missing tool tags are appended. Idempotent.
#
# Run from the repo root:  ruby tools/sync-tool-tags.rb
# CI runs it before the build, so a new writeup's tools become tags on their own.

require 'set'

REPO = File.expand_path('..', __dir__)

# Reuse the Arsenal's tool catalog and parser (single source of truth). The
# plugin's Jekyll hook is a no-op outside a build.
module Jekyll
  module Utils
    def self.slugify(s)
      s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
    end
  end

  module Hooks
    def self.register(*); end
  end
end

load File.join(REPO, '_plugins', 'arsenal.rb')

TAGS_RE = /^(tags:\s*\[)(.*)(\])\s*$/.freeze

# Canonical tool name -> the tag spelling to use (lowercase, to match the
# existing tag style; the tag page slug is the same either way).
def tool_tag(canonical)
  canonical.downcase
end

# The English post's "## Tools Used" table -> the set of tool tags it implies.
def tools_for(en_path)
  text = File.read(en_path, encoding: 'utf-8')
  table = text[/^##\s+Tools Used\s*\n(.*?)(?=^##\s|\z)/m, 1]
  return [] unless table

  tags = []
  seen = Set.new
  table.lines.select { |l| l.strip.start_with?('|') }.drop(2).each do |row|
    cell = row.strip.sub(/^\|/, '').split('|').first.to_s.strip
    Arsenal.tool_tokens(cell).each do |token|
      hit = Arsenal.match_tool(token)
      canon = hit ? hit[0] : token
      tag = tool_tag(canon)
      slug = Jekyll::Utils.slugify(tag)
      next if slug.empty? || seen.include?(slug)

      seen << slug
      tags << tag
    end
  end
  tags
end

def split_tags(inner)
  inner.split(',').map { |t| t.strip }.reject(&:empty?)
end

# Add `new_tags` to a post file's tag list (by slug), keeping existing ones and
# their order. Returns true if the file changed.
def add_tags(path, new_tags)
  text = File.read(path, encoding: 'utf-8')
  m = text.match(TAGS_RE)
  return false unless m

  existing = split_tags(m[2])
  have = existing.map { |t| Jekyll::Utils.slugify(t.gsub(/["']/, '')) }.to_set

  added = new_tags.reject { |t| have.include?(Jekyll::Utils.slugify(t)) }
  return false if added.empty?

  line = m[1] + (existing + added).join(', ') + m[3]
  File.write(path, text[0...m.begin(0)] + line + text[m.end(0)..])
  added
end

changed = 0
total_added = 0
Dir.glob(File.join(REPO, '_posts', 'en', '*.md')).sort.each do |en|
  tags = tools_for(en)
  next if tags.empty?

  base = File.basename(en)
  [en, File.join(REPO, '_posts', 'es', base)].each do |path|
    next unless File.file?(path)

    added = add_tags(path, tags)
    next unless added

    changed += 1
    total_added += added.size
    puts "#{path.sub(REPO + '/', '')}: +#{added.size} (#{added.join(', ')})"
  end
end

puts "tool tags: #{total_added} added across #{changed} files"
