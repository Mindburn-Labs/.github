#!/usr/bin/env ruby
# frozen_string_literal: true

require "open3"

REPO_ROOT = File.expand_path("..", __dir__)

RETIRED_ORG_SLUG = ["app", "mindburn", "web", "labs"].join("-")
BANNED_TERMS = {
  RETIRED_ORG_SLUG => "Use canonical GitHub organization 'Mindburn-Labs'."
}.freeze

def tracked_files
  stdout, stderr, status = Open3.capture3("git", "-C", REPO_ROOT, "ls-files", "-z")
  raise "git ls-files failed: #{stderr}" unless status.success?

  stdout.split("\0").reject(&:empty?)
end

def text_for(path)
  File.binread(File.join(REPO_ROOT, path)).encode("UTF-8", invalid: :replace, undef: :replace)
end

matches = []

tracked_files.each do |path|
  content = text_for(path)

  BANNED_TERMS.each do |term, hint|
    content.each_line.with_index(1) do |line, line_number|
      next unless line.include?(term)

      matches << [path, line_number, line.chomp, hint]
    end
  end
end

if matches.empty?
  puts "org rename guard passed"
  exit 0
end

warn "org rename guard failed: banned retired org slug detected"
matches.each do |path, line_number, line, hint|
  warn "#{path}:#{line_number}: #{line}"
  warn "  #{hint}"
end

exit 1
