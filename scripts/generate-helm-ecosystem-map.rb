#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"
require "yaml"
require_relative "generate-repo-inventory"
require_relative "helm-ecosystem-map-markdown"

REPO_ROOT = File.expand_path("..", __dir__)
WORKSPACE_ROOT = ENV.fetch("MINDBURN_WORKSPACE_ROOT") { File.expand_path("..", REPO_ROOT) }
MANIFEST_PATH = File.join(REPO_ROOT, "repo-manifest.yaml")
MANIFEST_LOCAL_POLICY_PATH = File.join(REPO_ROOT, "manifest-local-policy.yaml")
COMPATIBILITY_POLICY_PATH = File.join(REPO_ROOT, "local-compatibility-policy.yaml")
ESTATE_INVENTORY_PATH = File.join(WORKSPACE_ROOT, "production-readiness", "estate", "estate-inventory.json")
MIGRATION_INDEX_PATH = File.join(WORKSPACE_ROOT, "production-readiness", "estate", "migration-index.json")
TEAM_DOC_PATH = File.join(WORKSPACE_ROOT, "docs_for_team", "docs", "onboarding", "helm-ecosystem-directory-map.md")
ROOT_DOC_PATH = File.join(WORKSPACE_ROOT, "docs", "architecture", "helm-ecosystem-directory-map.md")
HANDBOOK_DOC_PATH = File.join(WORKSPACE_ROOT, "docs-engineering-handbook", "docs", "architecture", "helm-ecosystem-directory-map.md")

OPTIONS = {
  write: false,
  check: false,
  json: false
}.freeze

def usage
  "Usage: ruby scripts/generate-helm-ecosystem-map.rb [--write|--check|--json] [--output PATH] [--legacy-snapshots]"
end

options = OPTIONS.dup
OptionParser.new do |parser|
  parser.banner = usage
  parser.on("--write", "Write generated Markdown outputs") { options[:write] = true }
  parser.on("--check", "Fail if generated outputs are stale or invalid") { options[:check] = true }
  parser.on("--json", "Print machine-readable summary") { options[:json] = true }
  parser.on("--output PATH", "Limit generated output to this path (repeatable)") { |path| (options[:outputs] ||= []) << File.expand_path(path) }
  parser.on("--legacy-snapshots", "Include capture-only local classification and migration snapshots; both must exist") { options[:legacy] = true }
end.parse!
output_paths = options.fetch(:outputs, [TEAM_DOC_PATH, ROOT_DOC_PATH, HANDBOOK_DOC_PATH])

if !options[:write] && !options[:check] && !options[:json]
  warn usage
  exit 2
end

def read_yaml(path, required: true)
  if !File.exist?(path)
    raise "#{path} is missing" if required

    return {}
  end

  YAML.safe_load(File.read(path), permitted_classes: [Date, Time], aliases: true) || {}
end

def read_json(path, required: true)
  if !File.exist?(path)
    hint = if path == MIGRATION_INDEX_PATH
             " The retired root inventory script produced this legacy snapshot; current ecp reports do not replace it."
           elsif path == ESTATE_INVENTORY_PATH
             " Run from a full Mindburn workspace checkout, not a repo-only checkout."
           else
             ""
           end
    raise "#{path} is missing.#{hint}" if required

    return {}
  end

  JSON.parse(File.read(path))
end

def migration_entries
  read_json(MIGRATION_INDEX_PATH).fetch("entries")
end

def manifest_policy
  read_yaml(MANIFEST_LOCAL_POLICY_PATH)
end

def compatibility_policy
  read_yaml(COMPATIBILITY_POLICY_PATH)
end

def estate_by_name(entries)
  entries.each_with_object({}) { |entry, memo| memo[entry.fetch("name")] = entry }
end

def build_state(legacy_snapshots: false)
  manifest = read_yaml(MANIFEST_PATH)
  derived_summary = RepoInventory.derive(manifest)
  unless derived_summary.all? { |key, value| manifest.fetch("inventory_summary")[key] == value }
    raise "manifest summary is stale; run scripts/generate-repo-inventory.rb --write"
  end
  estate_inventory = legacy_snapshots ? read_json(ESTATE_INVENTORY_PATH) : { "entries" => [] }
  migration_index = legacy_snapshots ? read_json(MIGRATION_INDEX_PATH) : { "entries" => [] }
  estate_entries = estate_inventory.fetch("entries")
  manifest_policy = manifest_policy()
  compat_policy = compatibility_policy()

  {
    manifest: manifest,
    legacy_snapshots: legacy_snapshots,
    manifest_summary: manifest.fetch("inventory_summary"),
    manifest_repos: manifest.fetch("repositories"),
    estate_by_name: estate_by_name(estate_entries),
    aliases: manifest_policy.fetch("aliases", {}),
    manifest_only_policy: manifest_policy.fetch("manifest_only", {}),
    compat_policy: compat_policy,
    migration_entries: migration_index.fetch("entries")
  }
end

def validate_state!(state, markdown)
  errors = []
  manifest_names = state.fetch(:manifest_repos).map { |repo| repo.fetch("name") }
  aliases = state.fetch(:aliases)
  manifest_only_policy = state.fetch(:manifest_only_policy)
  compat_policy = state.fetch(:compat_policy).fetch("compatibility_directories", {})

  aliases.each do |manifest_name, policy|
    errors << "alias #{manifest_name} is not a manifest repo" unless manifest_names.include?(manifest_name)
    errors << "alias #{manifest_name} local path is empty" if policy.fetch("local_path").to_s.empty?
  end

  manifest_only_policy.each_key do |name|
    errors << "manifest-only policy #{name} is not a manifest repo" unless manifest_names.include?(name)
  end

  state.fetch(:manifest_summary).fetch("archived_repositories").each do |name|
    errors << "archived repository #{name} is not present in manifest repo names" unless manifest_names.include?(name)
  end
  state.fetch(:manifest_summary).fetch("deleted_repositories", []).each do |name|
    errors << "deleted repository #{name} is still present in manifest repo names" if manifest_names.include?(name)
  end

  production_status = state.fetch(:manifest_summary).fetch("production_release_status")
  errors << "generated Markdown production status does not match manifest" unless markdown.include?("production_release_status: #{production_status}")

  rendered_manifest_rows = markdown.scan(/^\| [^|]+ \| `([^`]+)` \| `(?:public|private|internal)` \|/).flatten
  missing_from_manifest_table = manifest_names - rendered_manifest_rows
  extra_manifest_rows = rendered_manifest_rows - manifest_names
  duplicate_manifest_rows = rendered_manifest_rows.tally.select { |_, count| count > 1 }.keys
  errors << "manifest repos missing from manifest table: #{missing_from_manifest_table.join(", ")}" unless missing_from_manifest_table.empty?
  errors << "non-manifest repos in manifest table: #{extra_manifest_rows.join(", ")}" unless extra_manifest_rows.empty?
  errors << "duplicate manifest table repos: #{duplicate_manifest_rows.join(", ")}" unless duplicate_manifest_rows.empty?

  wt_manifest_rows = rendered_manifest_rows.select { |name| name.include?("-wt-") }
  errors << "`*-wt-*` directories appear in manifest table: #{wt_manifest_rows.join(", ")}" unless wt_manifest_rows.empty?

  worktree_rows = markdown.scan(/^\| `([^`]*-wt-[^`]*)` \|/).flatten
  errors << "transient worktree directories appear in generated map: #{worktree_rows.join(", ")}" unless worktree_rows.empty?

  compat_policy.each_key do |name|
    errors << "compatibility policy #{name} missing from generated Markdown" unless markdown.include?("`#{name}`")
  end

  errors << "legacy migration index has no entries" if state.fetch(:legacy_snapshots) && state.fetch(:migration_entries).empty?
  raise errors.join("\n") unless errors.empty?
end

def write_outputs(markdown, paths)
  paths.each do |path|
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, markdown)
  end
end

state = build_state(legacy_snapshots: options.fetch(:legacy, false))
markdown = HelmEcosystemMapMarkdown.render(state)
validate_state!(state, markdown)

if options[:write]
  write_outputs(markdown, output_paths)
  output_paths.each { |path| puts "Wrote #{path}" }
end

if options[:check]
  expected = output_paths.to_h { |path| [path, markdown] }
  stale = expected.filter_map do |path, content|
    if !File.exist?(path)
      "#{path} is missing"
    elsif File.read(path) != content
      "#{path} is stale"
    end
  end
  raise stale.join("\n") unless stale.empty?

  puts "HELM ecosystem map is current"
end

if options[:json]
  summary = {
    "workspace_root" => WORKSPACE_ROOT,
    "manifest_repositories" => state.fetch(:manifest_repos).count,
    "workstation_directories_included" => false,
    "migration_entries" => state.fetch(:migration_entries).count,
    "outputs" => output_paths,
    "legacy_snapshots_included" => state.fetch(:legacy_snapshots)
  }
  puts JSON.pretty_generate(summary)
end
