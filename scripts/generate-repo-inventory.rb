#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "json"
require "optparse"
require "yaml"

# Only per-repository entries determine counts. Deleted history and release
# policy remain source-owned fields, never derived from repository inventory.
module RepoInventory
  BEGIN_MARKER = "<!-- BEGIN GENERATED REPOSITORY INVENTORY -->"
  END_MARKER = "<!-- END GENERATED REPOSITORY INVENTORY -->"
  VISIBILITIES = %w[public private internal].freeze
  module_function

  def derive(manifest)
    rows = manifest.fetch("repositories")
    raise "repositories must be a nonempty array" unless rows.is_a?(Array) && !rows.empty?

    names = []
    rows.each do |row|
      raise "invalid repository row" unless row.is_a?(Hash) && row["name"].is_a?(String) && !row["name"].empty?
      raise "invalid visibility for #{row['name']}" unless VISIBILITIES.include?(row["visibility"])
      raise "archived must be boolean for #{row['name']}" unless [true, false].include?(row["archived"])

      names << row.fetch("name")
    end
    raise "duplicate repository names" unless names.uniq.length == names.length
    deleted = manifest.fetch("inventory_summary").fetch("deleted_repositories", [])
    raise "deleted repositories still have rows" unless (names & deleted).empty?

    {
      "total_repositories" => rows.length,
      "active_repositories" => rows.count { |row| !row.fetch("archived") },
      "archived_repositories" => rows.select { |row| row.fetch("archived") }.map { |row| row.fetch("name") }.sort,
      "public_repositories" => rows.select { |row| row.fetch("visibility") == "public" }.map { |row| row.fetch("name") }.sort,
      "internal_repositories" => rows.select { |row| row.fetch("visibility") == "internal" }.map { |row| row.fetch("name") }.sort
    }
  end

  def reconcile!(manifest, github)
    raise "GitHub inventory must be an array" unless github.is_a?(Array)

    remote = github.map do |row|
      raise "GitHub archived must be boolean" unless [true, false].include?(row.fetch("isArchived"))
      visibility = row.fetch("visibility").downcase
      raise "invalid GitHub visibility" unless VISIBILITIES.include?(visibility)

      [row.fetch("name"), [visibility, row.fetch("isArchived")]]
    end
    raise "duplicate GitHub repository names" unless remote.map(&:first).uniq.length == remote.length

    local = manifest.fetch("repositories").map { |row| [row.fetch("name"), [row.fetch("visibility"), row.fetch("archived")]] }.to_h
    raise "manifest repository entries differ from GitHub readback; reconcile entries first" unless local == remote.to_h
  end

  def block(manifest, summary)
    private_count = manifest.fetch("repositories").count { |row| row.fetch("visibility") == "private" }
    public_names = summary.fetch("public_repositories")
    internal_names = summary.fetch("internal_repositories")
    format_names = ->(names) { names.empty? ? "none" : names.map { |name| "`#{name}`" }.join(", ") }
    [
      BEGIN_MARKER,
      "#{summary.fetch('total_repositories')} repositories: #{summary.fetch('active_repositories')} active, #{summary.fetch('archived_repositories').length} archived; #{public_names.length} public, #{private_count} private, #{internal_names.length} internal.",
      "",
      "Public repositories: #{format_names.call(public_names)}.",
      "",
      "Internal repositories: #{format_names.call(internal_names)}.",
      END_MARKER
    ].join("\n")
  end

  def replace_block(text, content)
    raise "expected one inventory block" unless text.scan(BEGIN_MARKER).length == 1 && text.scan(END_MARKER).length == 1
    pattern = /#{Regexp.escape(BEGIN_MARKER)}.*?#{Regexp.escape(END_MARKER)}/m
    raise "inventory block markers are out of order" unless text.match?(pattern)

    text.sub(pattern, content)
  end

  def run(argv)
    options = { root: File.expand_path("..", __dir__) }
    OptionParser.new do |parser|
      parser.banner = "Usage: generate-repo-inventory.rb (--check|--write) [--docs-root DIR] [--github-json FILE]"
      parser.on("--check") { options[:check] = true }
      parser.on("--write") { options[:write] = true }
      parser.on("--repo-root DIR") { |value| options[:root] = File.expand_path(value) }
      parser.on("--docs-root DIR") { |value| options[:docs] = File.expand_path(value) }
      parser.on("--github-json FILE") { |value| options[:github] = value }
    end.parse!(argv)
    raise "choose exactly one of --check and --write" unless !!options[:check] ^ !!options[:write]
    raise "unexpected arguments" unless argv.empty?

    manifest_path = File.join(options[:root], "repo-manifest.yaml")
    original = File.read(manifest_path)
    manifest = YAML.safe_load(original, permitted_classes: [Date, Time], aliases: false)
    summary = derive(manifest)
    reconcile!(manifest, JSON.parse(File.read(options[:github]))) if options[:github]
    merged = manifest.fetch("inventory_summary").merge(summary)
    raise "expected one top-level inventory_summary" unless original.scan(/^inventory_summary:/).length == 1
    summary_text = YAML.dump({ "inventory_summary" => merged }).sub(/\A---\n/, "")
    manifest_text = original.sub(/^inventory_summary:.*?(?=^[A-Za-z_]|\z)/m, summary_text)
    raise "inventory summary replacement failed" unless YAML.safe_load(manifest_text, permitted_classes: [Date, Time], aliases: false) == manifest.merge("inventory_summary" => merged)

    content = block(manifest, summary)
    targets = [File.join(options[:root], "README.md")]
    if options[:docs]
      targets.concat(%w[
        architecture/repo-topology.md
        plans/2026-09-29-estate-structure-and-migration.md
        architecture/helm-workspace-on-bb/REPO-CONSOLIDATION.md
      ].map { |path| File.join(options[:docs], path) })
    end
    # Validate every target before writing anything.
    outputs = { manifest_path => manifest_text }
    targets.each { |path| outputs[path] = replace_block(File.read(path), content) }
    stale = outputs.select { |path, expected| File.read(path) != expected }
    if options[:check]
      raise "stale inventory: #{stale.keys.join(', ')}; run with --write" unless stale.empty?
    else
      stale.each { |path, expected| File.write(path, expected) }
    end
    puts "Repository inventory #{options[:check] ? 'verified' : 'generated'}: #{summary.fetch('total_repositories')} repositories; #{outputs.length} source-derived files"
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    RepoInventory.run(ARGV)
  rescue StandardError => error
    warn error.message
    exit 1
  end
end
