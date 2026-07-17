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
# Output overrides allow cross-repository generation to target clean worktrees
# without mutating a developer's primary docs checkouts.
TEAM_DOC_PATH = ENV.fetch("MINDBURN_TEAM_DOC_PATH") do
  File.join(WORKSPACE_ROOT, "docs_for_team", "docs", "onboarding", "helm-ecosystem-directory-map.md")
end
ROOT_DOC_PATH = ENV.fetch("MINDBURN_ROOT_DOC_PATH") do
  File.join(WORKSPACE_ROOT, "docs", "architecture", "helm-ecosystem-directory-map.md")
end
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
  when "app-developer-portal", "app-helm-console", "app-mindburn-web"
    "Frontend / User Surfaces"
  when "app-docs-platform", "platform-design-system"
    "Archived UI / Design"
  when "pkg-mindburn-helm-ds", "pkg-mindburn-web-ds"
    "Design Systems"
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
  when "tempora"
    "Separate Product / Dogfood"
  else
    "Other Manifest Repository"
  end
end

def estate_by_name(entries)
  entries.each_with_object({}) { |entry, memo| memo[entry.fetch("name")] = entry }
end

def expected_workspace_path_for(name, aliases, manifest_only_policy)
  alias_entry = aliases[name]
  if alias_entry
    local_path = alias_entry["local_path"]
    return "alias `#{local_path}`" if local_path

    external_path = alias_entry["external_path"]
    return "external alias `#{external_path}`" if external_path
  end

  return "not required locally" if manifest_only_policy.key?(name)

  "`#{name}`"
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

def compatibility_policy_names(compat_policy)
  compat_policy.fetch("compatibility_directories", {}).keys.sort
end

def render_markdown(state)
  manifest_summary = state.fetch(:manifest_summary)
  manifest_repos = state.fetch(:manifest_repos)
  estate = state.fetch(:estate_by_name)
  aliases = state.fetch(:aliases)
  migration_entries = state.fetch(:migration_entries)
  compat_policy = state.fetch(:compat_policy)
  manifest_only_policy = state.fetch(:manifest_only_policy)

  manifest_rows = manifest_repos.sort_by { |repo| repo.fetch("name") }.map do |repo|
    name = repo.fetch("name")
    [
      group_for(name),
      "`#{name}`",
      "`#{repo.fetch("visibility")}`",
      expected_workspace_path_for(name, aliases, manifest_only_policy),
      manifest_classification(repo, estate[name])
    ]
  end

  manifest_only_rows = manifest_only_policy.sort_by { |name, _| name }.map do |name, policy|
    [
      "`#{name}`",
      "`not required locally`",
      policy.fetch("reason")
    ]
  end

  compat_rows = compatibility_policy_names(compat_policy).map do |name|
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

  lines = []
  lines << "---"
  lines << "title: HELM Ecosystem Directory Map"
  lines << "status: generated-canonical-source-map"
  lines << "generated_by: .github-repo/scripts/generate-helm-ecosystem-map.rb"
  lines << "manifest_repository_count: #{manifest_summary.fetch("total_repositories")}"
  lines << "active_repository_count: #{manifest_summary.fetch("active_repositories")}"
  lines << "production_release_status: #{manifest_summary.fetch("production_release_status")}"
  lines << "source_of_truth:"
  lines << "  - .github-repo/repo-manifest.yaml"
  lines << "  - .github-repo/manifest-local-policy.yaml"
  lines << "  - .github-repo/local-compatibility-policy.yaml"
  lines << "  - production-readiness/estate/estate-inventory.json"
  lines << "  - production-readiness/estate/migration-index.json"
  lines << "---"
  lines << ""
  lines << "# HELM Ecosystem Directory Map"
  lines << ""
  lines << "This file is generated. Do not edit it by hand."
  lines << ""
  lines << "> [!IMPORTANT]"
  lines << "> `$MINDBURN_WORKSPACE_ROOT` is a polyrepo workspace, not one git repository. `.github-repo/repo-manifest.yaml` controls GitHub repo existence, visibility, and archive status. `production-readiness/estate/estate-inventory.json` controls local path classification only. This committed map intentionally excludes temporal workstation directories."
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
      ["Deleted repositories", Array(manifest_summary.fetch("deleted_repositories", [])).empty? ? "none" : Array(manifest_summary.fetch("deleted_repositories")).map { |name| "`#{name}`" }.join(", ")],
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
  lines << "- Local `*-wt-*` directories are task checkout directories by naming convention, not separate products or canonical repos; this map never enumerates them."
  lines << "- Compatibility/local-only directories are not GitHub repository truth unless they appear in `.github-repo/repo-manifest.yaml`."
  lines << ""
  lines << "## Canonical Manifest Repositories"
  lines << ""
  lines.concat markdown_table(["Group", "Repository", "Visibility", "Expected workspace path", "Strict classification"], manifest_rows)
  lines << ""
  lines << "## Manifest Repository Local-Checkout Policy"
  lines << ""
  lines.concat markdown_table(["Repository", "Policy", "Reason"], manifest_only_rows.empty? ? [["none", "n/a", "all manifest repos use their expected workspace path"]] : manifest_only_rows)
  lines << ""
  lines << "## Workstation Inventory Boundary"
  lines << ""
  lines << "This committed map does not enumerate local-only directories, generated caches, or task worktrees. They change per machine and per task, so recording them here would make workstation state look like repository topology."
  lines << ""
  lines << "For a current local classification, generate and inspect `production-readiness/estate/estate-inventory.json` at the workspace root. That output is local evidence only; it does not change manifest repository truth."
  lines << ""
  lines << "## Compatibility Directory Policy"
  lines << ""
  lines << "This policy lists approved compatibility names; it does not assert that any such local directory exists."
  lines << ""
  lines.concat markdown_table(["Directory", "Status", "Canonical replacement", "Expires"], compat_rows.empty? ? [["none", "n/a", "n/a", "n/a"]] : compat_rows)
  lines << ""
  lines << "## Data, DB, And Migrations"
  lines << ""
  lines << "There is no standalone canonical `db-*` repository in the current manifest. Database and state ownership live inside owning repos."
  lines << ""
  lines << "The rows below are the versioned migration index, not a scan of local worktrees."
  lines << ""
  lines.concat markdown_table(["Path", "Owner repo", "Kind", "Manifest repo"], migration_rows)
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
  lines << "- Validate with `.github-repo/scripts/generate-helm-ecosystem-map.rb --check` from a workspace that contains the source files and both generated-map paths."
  lines << "- Intentionally refresh the local estate and generated maps with `.github-repo/scripts/refresh-helm-ecosystem-map.sh`; do not use a transient worktree list as committed topology."
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
    local_path = policy["local_path"]
    external_path = policy["external_path"]
    if local_path && external_path
      errors << "alias #{manifest_name} must define only one of local_path or external_path"
    elsif local_path
      errors << "alias #{manifest_name} local path is empty" if local_path.to_s.empty?
    elsif external_path
      if external_path.to_s.empty?
        errors << "alias #{manifest_name} external path is empty"
      elsif Pathname.new(external_path).absolute?
        errors << "alias #{manifest_name} external path must be relative to the workspace root"
      end
    else
      errors << "alias #{manifest_name} must define local_path or external_path"
    end
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
    "workstation_directories_included" => false,
    "migration_entries" => state.fetch(:migration_entries).count,
    "outputs" => [TEAM_DOC_PATH, ROOT_DOC_PATH]
  }
  puts JSON.pretty_generate(summary)
end
