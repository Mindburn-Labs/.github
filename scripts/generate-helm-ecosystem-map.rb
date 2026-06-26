#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"
require "yaml"

REPO_ROOT = File.expand_path("..", __dir__)
WORKSPACE_ROOT = ENV.fetch("MINDBURN_WORKSPACE_ROOT") { File.expand_path("..", REPO_ROOT) }
MANIFEST_PATH = File.join(REPO_ROOT, "repo-manifest.yaml")
MANIFEST_LOCAL_POLICY_PATH = File.join(REPO_ROOT, "manifest-local-policy.yaml")
COMPATIBILITY_POLICY_PATH = File.join(REPO_ROOT, "local-compatibility-policy.yaml")
ESTATE_INVENTORY_PATH = File.join(WORKSPACE_ROOT, "production-readiness", "estate", "estate-inventory.json")
MIGRATION_INDEX_PATH = File.join(WORKSPACE_ROOT, "production-readiness", "estate", "migration-index.json")
TEAM_DOC_PATH = File.join(WORKSPACE_ROOT, "docs_for_team", "docs", "onboarding", "helm-ecosystem-directory-map.md")
ROOT_DOC_PATH = File.join(WORKSPACE_ROOT, "docs", "architecture", "helm-ecosystem-directory-map.md")
ROUTING_DOC_PATH = File.join(WORKSPACE_ROOT, "docs_for_team", "docs", "onboarding", "helm-task-routing.md")

OPTIONS = {
  write: false,
  check: false,
  json: false
}.freeze

def usage
  "Usage: ruby scripts/generate-helm-ecosystem-map.rb [--write|--check|--json]"
end

options = OPTIONS.dup
OptionParser.new do |parser|
  parser.banner = usage
  parser.on("--write", "Write generated Markdown outputs") { options[:write] = true }
  parser.on("--check", "Fail if generated outputs are stale or invalid") { options[:check] = true }
  parser.on("--json", "Print machine-readable summary") { options[:json] = true }
end.parse!

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
             " Run `ruby scripts/estate-control-plane.rb` from the workspace root first."
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

def top_level_directories
  raise "#{WORKSPACE_ROOT} is missing" unless Dir.exist?(WORKSPACE_ROOT)

  Dir.children(WORKSPACE_ROOT).select do |name|
    File.directory?(File.join(WORKSPACE_ROOT, name))
  end.sort
end

def manifest_repositories
  read_yaml(MANIFEST_PATH).fetch("repositories")
end

def inventory_entries
  read_json(ESTATE_INVENTORY_PATH).fetch("entries")
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

def group_for(name)
  case name
  when ".github"
    "GitHub Metadata"
  when "app-developer-portal"
    "Frontend / User Surfaces"
  when "app-helm-console", "app-docs-platform", "app-mindburn-web", "platform-design-system"
    "Archived UI / Design"
  when "helm-ai-kernel", "helm-ai-enterprise", "helm-agent-integrations", "helm-compiler-lab", "worker-helm-launch-worker", "helm-rollout-evidence"
    "HELM Core / Product"
  when /^svc-/
    "Backend / Runtime Services"
  when "contracts-catalog"
    "Contracts / Schemas"
  when /^integration-/
    "Integration / Evaluation / Release Evidence"
  when /^platform-/
    "Platform / Policy Substrate"
  when /^infra-/, /^gitops-/, "mindburn-infra"
    "Infrastructure / GitOps"
  when "docs-engineering-handbook", "docs_for_team", "dev-orchestration", "homebrew-tap"
    "Docs / Onboarding / Local Ops"
  when "ml-orggenome-compiler"
    "OrgGenome / ML"
  else
    "Other Manifest Repository"
  end
end

def estate_by_name(entries)
  entries.each_with_object({}) { |entry, memo| memo[entry.fetch("name")] = entry }
end

def local_checkout_for(name, local_dirs, aliases)
  return "yes" if local_dirs.include?(name)

  alias_entry = aliases[name]
  return "alias `#{alias_entry.fetch("local_path")}`" if alias_entry && local_dirs.include?(alias_entry.fetch("local_path"))

  "no"
end

def strict_classification(name, estate_entry)
  return "manifest-only; local estate entry absent" unless estate_entry

  kind = estate_entry["kind"]
  domain = estate_entry["domain"]
  system = estate_entry["system"]
  lifecycle = estate_entry["lifecycle_state"]
  "`#{kind}`; #{domain} / #{system}; lifecycle `#{lifecycle}`"
end

def manifest_classification(repo, estate_entry)
  return strict_classification(repo.fetch("name"), estate_entry) unless repo["archived"] == true

  if estate_entry
    "`archived_repo`; #{estate_entry["domain"]} / #{estate_entry["system"]}; lifecycle `archived`"
  else
    "`archived_repo`; manifest archived"
  end
end

def markdown_table(headers, rows)
  lines = []
  lines << "| #{headers.join(" | ")} |"
  lines << "| #{headers.map { "---" }.join(" | ")} |"
  rows.each { |row| lines << "| #{row.join(" | ")} |" }
  lines
end

def compatibility_dirs(local_dirs, estate_entries)
  from_estate = estate_entries.select { |entry| entry["kind"] == "compatibility_repo" }.map { |entry| entry["name"] }
  from_names = local_dirs.select { |name| name.match?(/\Acontracts-(api|event|proto|schema)-catalog\z/) || name.match?(/\Apkg-helm-client-/) }
  (from_estate + from_names).uniq.sort
end

def local_classification(name, estate_entry, compat_policy)
  return "task checkout directory by naming convention" if name.include?("-wt-")

  if compat_policy.fetch("compatibility_directories", {}).key?(name)
    policy = compat_policy.fetch("compatibility_directories").fetch(name)
    return "compatibility; canonical `#{policy.fetch("canonical")}`; action `#{policy.fetch("action")}`; expires `#{policy.fetch("expires")}`"
  end

  return strict_classification(name, estate_entry) if estate_entry

  "local directory; no estate entry"
end

def render_markdown(state)
  manifest_summary = state.fetch(:manifest_summary)
  manifest_repos = state.fetch(:manifest_repos)
  estate = state.fetch(:estate_by_name)
  local_dirs = state.fetch(:local_dirs)
  aliases = state.fetch(:aliases)
  migration_entries = state.fetch(:migration_entries)
  compat_policy = state.fetch(:compat_policy)
  manifest_only_policy = state.fetch(:manifest_only_policy)
  generated_at = state.fetch(:generated_at)
  snapshot_date = Date.parse(generated_at).iso8601

  manifest_rows = manifest_repos.sort_by { |repo| repo.fetch("name") }.map do |repo|
    name = repo.fetch("name")
    [
      group_for(name),
      "`#{name}`",
      "`#{repo.fetch("visibility")}`",
      local_checkout_for(name, local_dirs, aliases),
      manifest_classification(repo, estate[name])
    ]
  end

  manifest_names = manifest_repos.map { |repo| repo.fetch("name") }
  alias_local_paths = aliases.values.map { |entry| entry.fetch("local_path") }
  local_only_names = local_dirs.reject { |name| manifest_names.include?(name) }.sort
  local_only_rows = local_only_names.map do |name|
    [
      "`#{name}`",
      alias_local_paths.include?(name) ? "manifest alias target" : "local-only",
      local_classification(name, estate[name], compat_policy)
    ]
  end

  missing_rows = manifest_repos.filter_map do |repo|
    name = repo.fetch("name")
    checkout = local_checkout_for(name, local_dirs, aliases)
    next unless checkout == "no"

    policy = manifest_only_policy[name]
    [
      "`#{name}`",
      policy ? "`policy-waived`" : "`BLOCKER`",
      policy ? policy.fetch("reason") : "missing local checkout and no manifest-only policy"
    ]
  end

  compat_rows = compatibility_dirs(local_dirs, state.fetch(:estate_entries)).map do |name|
    policy = compat_policy.fetch("compatibility_directories", {})[name]
    [
      "`#{name}`",
      policy ? "`policy-bound`" : "`BLOCKER`",
      policy ? "`#{policy.fetch("canonical")}`" : "missing",
      policy ? "`#{policy.fetch("expires")}`" : "missing"
    ]
  end

  migration_rows = migration_entries.sort_by { |entry| entry.fetch("path") }.map do |entry|
    [
      "`#{entry.fetch("path")}`",
      "`#{entry.fetch("owner_repo")}`",
      "`#{entry.fetch("kind")}`",
      entry.fetch("manifest_repo") ? "yes" : "no"
    ]
  end

  task_rows = local_dirs.select { |name| name.include?("-wt-") }.sort.map do |name|
    [
      "`#{name}`",
      "task checkout directory by naming convention",
      "not canonical repo truth"
    ]
  end

  lines = []
  lines << "---"
  lines << "title: HELM Ecosystem Directory Map"
  lines << "status: generated-strict-source-snapshot"
  lines << "snapshot_date: #{snapshot_date}"
  lines << "generated_at: #{generated_at}"
  lines << "generated_by: .github-repo/scripts/generate-helm-ecosystem-map.rb"
  lines << "manifest_repository_count: #{manifest_summary.fetch("total_repositories")}"
  lines << "active_repository_count: #{manifest_summary.fetch("active_repositories")}"
  lines << "production_release_status: #{manifest_summary.fetch("production_release_status")}"
  lines << "source_of_truth:"
  lines << "  - .github-repo/repo-manifest.yaml"
  lines << "  - production-readiness/estate/estate-inventory.json"
  lines << "  - production-readiness/estate/migration-index.json"
  lines << "---"
  lines << ""
  lines << "# HELM Ecosystem Directory Map"
  lines << ""
  lines << "This file is generated. Do not edit it by hand."
  lines << ""
  lines << "> [!IMPORTANT]"
  lines << "> `$MINDBURN_WORKSPACE_ROOT` is a polyrepo workspace, not one git repository. `.github-repo/repo-manifest.yaml` controls GitHub repo existence, visibility, and archive status. `production-readiness/estate/estate-inventory.json` controls local path classification only."
  lines << ""
  lines << "## Current Manifest Truth"
  lines << ""
  lines.concat markdown_table(
    ["Field", "Value"],
    [
      ["GitHub organization", "`#{read_yaml(MANIFEST_PATH).fetch("organization")}`"],
      ["Total repositories", "`#{manifest_summary.fetch("total_repositories")}`"],
      ["Active repositories", "`#{manifest_summary.fetch("active_repositories")}`"],
      ["Archived repositories", Array(manifest_summary.fetch("archived_repositories")).empty? ? "none" : Array(manifest_summary.fetch("archived_repositories")).map { |name| "`#{name}`" }.join(", ")],
      ["Production release status", "`#{manifest_summary.fetch("production_release_status")}`"],
      ["Production release source", "`#{manifest_summary.fetch("production_release_source")}`"],
      ["Production release evidence", "`#{manifest_summary.fetch("production_release_evidence")}`"]
    ]
  )
  lines << ""
  lines << "## Source Truth Rules"
  lines << ""
  lines << "- Code, route registries, schemas, generated contracts, release manifests, and GitOps evidence outrank prose docs."
  lines << "- UI code is never an authorization boundary."
  lines << "- RLM output is advisory evidence only; it does not verify HELM behavior by itself."
  lines << "- Local `*-wt-*` directories are task checkout directories by naming convention, not separate products or canonical repos."
  lines << "- Compatibility/local-only directories are not GitHub repository truth unless they appear in `.github-repo/repo-manifest.yaml`."
  lines << ""
  lines << "## Canonical Manifest Repositories"
  lines << ""
  lines.concat markdown_table(["Group", "Repository", "Visibility", "Local checkout", "Strict classification"], manifest_rows)
  lines << ""
  lines << "## Manifest Repositories Without Local Checkout"
  lines << ""
  lines.concat markdown_table(["Repository", "Status", "Reason"], missing_rows.empty? ? [["none", "n/a", "all manifest repos have local checkout or alias"]] : missing_rows)
  lines << ""
  lines << "## Local Directories Not In The Manifest"
  lines << ""
  lines.concat markdown_table(["Directory", "Relation", "Strict classification"], local_only_rows)
  lines << ""
  lines << "## Compatibility Directories"
  lines << ""
  lines.concat markdown_table(["Directory", "Status", "Canonical replacement", "Expires"], compat_rows.empty? ? [["none", "n/a", "n/a", "n/a"]] : compat_rows)
  lines << ""
  lines << "## Data, DB, And Migrations"
  lines << ""
  lines << "There is no standalone canonical `db-*` repository in the current manifest. Database and state ownership live inside owning repos."
  lines << ""
  lines.concat markdown_table(["Path", "Owner repo", "Kind", "Manifest repo"], migration_rows)
  lines << ""
  lines << "## Current Local `*-wt-*` Directories"
  lines << ""
  lines.concat markdown_table(["Directory", "Classification", "Authority"], task_rows.empty? ? [["none", "n/a", "n/a"]] : task_rows)
  lines << ""
  lines << "## Where To Start By Task"
  lines << ""
  lines << "This section is a routing aid, not source truth. See [[helm-task-routing]] for the shareable task-first version."
  lines << ""
  lines.concat markdown_table(
    ["If you are working on...", "Start here"],
    [
      ["Kernel verdicts, receipts, EvidencePacks, conformance", "`helm-ai-kernel`"],
      ["Paid HELM AI Enterprise backend/product logic", "`helm-ai-enterprise`, then `svc-helm-control-plane`"],
      ["Console UX", "Future React console repo; backend truth from `svc-helm-control-plane`"],
      ["Public docs", "Future website/docs React repo plus headless contract docs"],
      ["Public marketing site", "Future website/docs React repo"],
      ["Connector contracts or packs", "`helm-ai-enterprise`, `contracts-catalog`, `svc-helm-certification`, `integration-helm`"],
      ["Production release state", "`integration-mindburn-platform`, `gitops-apps`, `gitops-platform`"],
      ["Infrastructure/server access", "`mindburn-infra`, `docs_for_team`"],
      ["Agent substrate/RLM support", "`platform-agent-substrate`, `platform-agent-capabilities`, `svc-agent-sandbox-runner`"]
    ]
  )
  lines << ""
  lines << "## Obsidian Links"
  lines << ""
  lines << "- [[helm-task-routing]]"
  lines << "- [[repo-topology]]"
  lines << "- [[source-truth]]"
  lines << "- [[production-state]]"
  lines << "- [[helm-connector-pack-integration]]"
  lines << "- [[2026-estate-control-plane]]"
  lines << ""
  lines << "## Maintenance"
  lines << ""
  lines << "- Regenerate with `.github-repo/scripts/refresh-helm-ecosystem-map.sh`."
  lines << "- Do not promote compatibility directories into canonical ownership without a manifest/source-truth change."
  lines << "- Do not promote `*-wt-*` directories into product repos."
  lines << ""
  lines.join("\n")
end

def build_state
  manifest = read_yaml(MANIFEST_PATH)
  estate_inventory = read_json(ESTATE_INVENTORY_PATH)
  migration_index = read_json(MIGRATION_INDEX_PATH)
  estate_entries = estate_inventory.fetch("entries")
  manifest_policy = manifest_policy()
  compat_policy = compatibility_policy()

  {
    manifest: manifest,
    manifest_summary: manifest.fetch("inventory_summary"),
    manifest_repos: manifest.fetch("repositories"),
    generated_at: migration_index.fetch("generated_at", estate_inventory.fetch("generated_at")),
    estate_entries: estate_entries,
    estate_by_name: estate_by_name(estate_entries),
    local_dirs: top_level_directories,
    aliases: manifest_policy.fetch("aliases", {}),
    manifest_only_policy: manifest_policy.fetch("manifest_only", {}),
    compat_policy: compat_policy,
    migration_entries: migration_index.fetch("entries")
  }
end

def validate_state!(state, markdown)
  errors = []
  manifest_names = state.fetch(:manifest_repos).map { |repo| repo.fetch("name") }
  local_dirs = state.fetch(:local_dirs)
  aliases = state.fetch(:aliases)
  manifest_only_policy = state.fetch(:manifest_only_policy)
  compat_policy = state.fetch(:compat_policy).fetch("compatibility_directories", {})

  aliases.each do |manifest_name, policy|
    errors << "alias #{manifest_name} is not a manifest repo" unless manifest_names.include?(manifest_name)
    errors << "alias #{manifest_name} local path #{policy.fetch("local_path")} is missing" unless local_dirs.include?(policy.fetch("local_path"))
  end

  missing_manifest = manifest_names.reject do |name|
    local_dirs.include?(name) || (aliases[name] && local_dirs.include?(aliases[name].fetch("local_path"))) || manifest_only_policy.key?(name)
  end
  errors << "manifest repos missing locally without policy: #{missing_manifest.join(", ")}" unless missing_manifest.empty?

  compatibility_dirs(local_dirs, state.fetch(:estate_entries)).each do |name|
    errors << "compatibility directory #{name} is missing local-compatibility-policy.yaml entry" unless compat_policy.key?(name)
  end

  state.fetch(:manifest_summary).fetch("archived_repositories").each do |name|
    errors << "archived repository #{name} is not present in manifest repo names" unless manifest_names.include?(name)
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

  local_dirs.each do |name|
    errors << "local top-level directory #{name} missing from generated Markdown" unless markdown.include?("`#{name}`")
  end

  wt_manifest_rows = rendered_manifest_rows.select { |name| name.include?("-wt-") }
  errors << "`*-wt-*` directories appear in manifest table: #{wt_manifest_rows.join(", ")}" unless wt_manifest_rows.empty?

  errors << "migration index has no entries" if state.fetch(:migration_entries).empty?
  raise errors.join("\n") unless errors.empty?
end

def write_outputs(markdown)
  [TEAM_DOC_PATH, ROOT_DOC_PATH].each do |path|
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, markdown)
  end
end

state = build_state
markdown = render_markdown(state)
validate_state!(state, markdown)

if options[:write]
  write_outputs(markdown)
  puts "Wrote #{TEAM_DOC_PATH}"
  puts "Wrote #{ROOT_DOC_PATH}"
end

if options[:check]
  expected = {
    TEAM_DOC_PATH => markdown,
    ROOT_DOC_PATH => markdown
  }
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
    "local_directories" => state.fetch(:local_dirs).count,
    "migration_entries" => state.fetch(:migration_entries).count,
    "outputs" => [TEAM_DOC_PATH, ROOT_DOC_PATH]
  }
  puts JSON.pretty_generate(summary)
end
