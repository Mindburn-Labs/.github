#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "open3"
require "yaml"

repo_root = File.expand_path("..", __dir__)
workspace_root = ENV["MINDBURN_WORKSPACE_ROOT"]

unless workspace_root && !workspace_root.empty?
  puts "skipped headless UI reference scan: MINDBURN_WORKSPACE_ROOT is not set"
  exit 0
end

manifest = YAML.safe_load(
  File.read(File.join(repo_root, "repo-manifest.yaml")),
  permitted_classes: [Date, Time],
  aliases: true
)

aliases_path = File.join(repo_root, "manifest-local-policy.yaml")
aliases = if File.file?(aliases_path)
            YAML.safe_load(File.read(aliases_path), permitted_classes: [Date, Time], aliases: true).fetch("aliases", {})
          else
            {}
          end

banned = [
  "@mindburn/design",
  "platform-design-system",
  "app-docs-platform",
  "helm-console-web",
  "--console-assets",
  "Flutter web assets",
  "canonical Flutter console"
].freeze

banned_patterns = {
  "@mindburn/design" => /@mindburn\/design/,
  "platform-design-system" => /(?<![@A-Za-z0-9_.-])platform-design-system(?:-wt-[A-Za-z0-9_-]+)?(?![A-Za-z0-9_-]|\.(?:org|run|dev|com))/,
  "app-docs-platform" => /(?<![@A-Za-z0-9_.-])app-docs-platform(?:-wt-[A-Za-z0-9_-]+)?(?![A-Za-z0-9_-]|\.(?:org|run|dev|com))/,
  "helm-console-web" => /helm-console-web/,
  "--console-assets" => /--console-assets/,
  "Flutter web assets" => /Flutter web assets/,
  "canonical Flutter console" => /canonical Flutter console/
}.freeze

allowed_global = [
  %r{\AREPORTS/},
  %r{\A\.codex-security-scan/},
  %r{\ACHANGELOG\.md\z},
  %r{\Adocs/audit/.*\d{4}-\d{2}-\d{2}},
  %r{\A[^/]*audit[^/]*/.*\d{4}-\d{2}-\d{2}}
].freeze

allowed_by_repo = {
  ".github" => [
    %r{\Arepo-manifest\.yaml\z},
    %r{\Ascripts/check-retired-ui-surfaces\.rb\z},
    %r{\Ascripts/check-headless-ui-references\.rb\z},
    %r{\Ascripts/generate-helm-ecosystem-map\.rb\z}
  ],
  "docs_for_team" => [
    %r{\Adocs/onboarding/helm-ecosystem-directory-map\.md\z},
    %r{\Ascripts/check-headless-ui-reset\.rb\z}
  ],
  "gitops-apps" => [
    %r{\Ascripts/test-gitops-validator\.rb\z},
    %r{\Ascripts/validate-gitops-environments\.rb\z}
  ],
  "gitops-platform" => [
    %r{\Adocs/live-surfaces-ownership\.md\z},
    %r{\Adocs/release-authority-closure-board\.md\z}
  ],
  "helm-ai-kernel" => [
    %r{\A\.gitignore\z},
    %r{\Ascripts/release/dry_run\.sh\z}
  ],
  "integration-mindburn-platform" => [
    %r{\Amanifests/final-state-evidence\.yaml\z},
    %r{\Ascripts/test-release-manifest-validator\.rb\z},
    %r{\Ascripts/validate-release-manifest\.rb\z}
  ],
  "dev-orchestration" => [
    %r{\Aestate-control-plane/production-readiness/estate/.*proof.*},
    %r{\Aestate-control-plane/production-readiness/estate/rlm-handoff-.*},
    %r{\Aestate-control-plane/production-readiness/estate/estate-scorecard\.md\z}
  ]
}.freeze

def allowed_path?(repo_name, path, allowed_global, allowed_by_repo)
  return true if allowed_global.any? { |pattern| path.match?(pattern) }

  allowed_by_repo.fetch(repo_name, []).any? { |pattern| path.match?(pattern) }
end

def checkout_path(workspace_root, repo, aliases)
  name = repo.fetch("name")
  alias_entry = aliases[name]
  local_name = alias_entry ? alias_entry.fetch("local_path") : name
  File.join(workspace_root, local_name)
end

def grep_ref(repo_dir, pattern)
  ref = ENV.fetch("HEADLESS_UI_REFERENCE_REF", "origin/main")
  out, err, status = Open3.capture3("git", "-C", repo_dir, "grep", "-n", "-I", "-E", pattern, ref, "--")
  return [out, ref] if status.success?

  head_out, _head_err, head_status = Open3.capture3("git", "-C", repo_dir, "grep", "-n", "-I", "-E", pattern, "HEAD", "--")
  return [head_out, "HEAD"] if head_status.success?

  return ["", ref] if [0, 1].include?(status.exitstatus) || [0, 1].include?(head_status.exitstatus)

  warn "headless UI reference scan skipped #{repo_dir}: #{err.strip}"
  ["", ref]
end

grep_pattern = Regexp.union(banned.map { |term| Regexp.escape(term) }).source
errors = []

manifest.fetch("repositories").each do |repo|
  next if repo["archived"] == true

  repo_name = repo.fetch("name")
  repo_dir = checkout_path(workspace_root, repo, aliases)
  next unless Dir.exist?(repo_dir)

  out, ref = grep_ref(repo_dir, grep_pattern)
  out.each_line do |line|
    _prefix, path, line_no, text = line.split(":", 4)
    next unless path && line_no && text
    next if allowed_path?(repo_name, path, allowed_global, allowed_by_repo)

    needle = banned_patterns.find { |_label, candidate| text.match?(candidate) }&.first
    next unless needle

    errors << "#{repo_name}:#{ref}:#{path}:#{line_no}: retired UI/design reference #{needle}"
  end
end

if errors.any?
  warn errors.join("\n")
  exit 1
end

puts "headless UI reference scan passed"
