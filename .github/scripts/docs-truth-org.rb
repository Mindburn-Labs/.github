#!/usr/bin/env ruby
# frozen_string_literal: true

require "csv"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "pathname"
require "tmpdir"
require "time"
require "yaml"

REQUIRED_LEDGER_COLUMNS = %w[
  repo
  path
  status
  owner
  truth_kind
  source_refs
  truth_gate
  public_surface
  superseded_by
  notes
].freeze

ALLOWED_STATUSES = %w[active generated archive delete fix].freeze
MANIFEST_LOCAL_ALIASES = { ".github" => ".github-repo" }.freeze
ARCHIVE_WORDING = /\b(archive|archived|historical|superseded|retired|deleted|tombstone|read-only)\b/i
NO_CURRENT_SOURCE_WORDING = /\b(no current|historical only|historical-only|retention only|retained for history)\b/i

IGNORED_MARKDOWN_PATHS = [
  %r{\A\.git/},
  %r{\A(?:node_modules|vendor|dist|build|coverage|out|\.next|\.turbo|\.cache|tmp|temp)/},
  %r{/(?:node_modules|vendor|dist|build|coverage|out|\.next|\.turbo|\.cache|tmp|temp)/}
].freeze

DOCS_TRUTH_CONFIG = "docs-truth.yaml"

BANNED_STALE_PATTERNS = [
  [/app-mindburn-web\.org/i, "banned app-mindburn-web.org domain"],
  [/\bapp-docs-platform\b/i, "retired app-docs-platform repo name"],
  [/\bplatform-design-system\b/i, "retired platform-design-system repo name"],
  [/\bsvc-titan-proofd\b/i, "retired titan proof daemon name"],
  [/\bHELM Notary\b/, "fabricated HELM Notary wording"],
  [/production-grade sovereign microservice/i, "fabricated service README template"],
  [/Prometheus\s+:2112\/metrics/i, "fabricated Prometheus port claim"],
  [/OTel\s+:4317/i, "fabricated OTel port claim"]
].freeze

PUBLIC_CLAIM_PATTERNS = [
  [/\bproduction(?:-ready| ready| release| deployment| live)?\b/i, "production"],
  [/\bGA\b|\bgeneral availability\b/i, "GA"],
  [/\bcheckout\b/i, "checkout"],
  [/\bpricing\b/i, "pricing"],
  [/\bcustomer(?:s)?\b/i, "customer"],
  [/\bcertification\b|\bconnector-certified\b|\bcertified\b/i, "certification"],
  [/\bcompliance\b|\bcompliant\b|\bSOC 2\b|\bHIPAA\b|\bCMMC\b|\bISO\/IEC 42001\b/i, "compliance"],
  [/\blive deployment\b|\blive-deployment\b/i, "live-deployment"]
].freeze

SOURCE_CHANGE_EXTENSIONS = %w[
  .go .rs .ts .tsx .js .jsx .mjs .cjs .py .rb .java .kt .swift .sql .graphql
  .proto .json .yaml .yml .toml .tf .cue
].freeze

SOURCE_CHANGE_PATHS = [
  %r{\A(?:src|app|apps|core|cmd|internal|pkg|services|service|routes|api|apis|openapi|proto|schema|schemas|events|migrations|manifests|content|contracts|protocols|sdk)/},
  %r{/(?:src|app|apps|core|cmd|internal|pkg|services|service|routes|api|apis|openapi|proto|schema|schemas|events|migrations|manifests|content|contracts|protocols|sdk)/},
  %r{\A(?:Makefile|package\.json|pnpm-lock\.yaml|package-lock\.json|go\.mod|Cargo\.toml|pyproject\.toml)\z}
].freeze

SOURCE_OWNED_REF = %r{
  (^|:)
  (
    src|app|apps|core|cmd|internal|pkg|services|service|routes|api|apis|openapi|
    proto|schema|schemas|events|migrations|manifests|content|contracts|protocols|
    sdk|Makefile|package\.json|go\.mod|Cargo\.toml|pyproject\.toml|release|
    EvidencePack|ProofGraph|receipt|receipts|repo-manifest\.yaml|catalog-info\.yaml|
    agent\.yaml|content/claims\.json|content/route-manifest\.json
  )
}ix.freeze

class DocsTruthGate
  attr_reader :options

  def initialize(options)
    @options = options
    @workspace_root = File.expand_path(options.fetch(:workspace_root))
    @failures = []
    @warnings = []
    @repo_reports = {}
    @commands = []
  end

  def evaluate
    bootstrap_remote_manifest if options[:mode] == "remote"
    manifest = load_manifest
    selected = selected_repos(manifest)
    ensure_remote_repos(manifest, selected) if options[:mode] == "remote"

    ledger = load_ledger
    source_truth = load_source_truth

    selected.each do |repo|
      evaluate_repo(repo, manifest, ledger, source_truth)
    end

    report = {
      "generated_at" => Time.now.utc.iso8601,
      "mode" => options[:mode],
      "workspace_root" => @workspace_root,
      "selected_repos" => selected.map { |repo| repo.fetch("name") },
      "summary" => {
        "status" => @failures.empty? ? "PASS" : "FAIL",
        "repo_count" => selected.length,
        "failure_count" => @failures.length,
        "warning_count" => @warnings.length
      },
      "failures" => @failures,
      "warnings" => @warnings,
      "repos" => @repo_reports,
      "commands" => @commands
    }
    write_report(report)
    report
  end

  private

  def load_manifest
    path = first_existing([
      File.join(@workspace_root, ".github-repo", "repo-manifest.yaml"),
      File.join(@workspace_root, ".github", "repo-manifest.yaml"),
      File.join(@workspace_root, "repo-manifest.yaml")
    ])
    fail_global("manifest_missing", "missing .github-repo/repo-manifest.yaml under #{@workspace_root}") unless path

    raw = YAML.safe_load(File.read(path), permitted_classes: [Date, Time], aliases: true) || {}
    raw["__path"] = path
    raw["repositories"] ||= []
    raw
  rescue Psych::Exception => error
    fail_global("manifest_invalid", "#{path}: #{error.message}")
    { "repositories" => [], "__path" => path }
  end

  def load_ledger
    path = first_existing([
      File.join(@workspace_root, "docs", "audit", "markdown-estate-ledger.csv"),
      File.join(@workspace_root, "audit", "markdown-estate-ledger.csv")
    ])
    fail_global("ledger_missing", "missing docs/audit/markdown-estate-ledger.csv under #{@workspace_root}") unless path

    rows = CSV.read(path, headers: true)
    headers = Array(rows.headers).compact
    missing = REQUIRED_LEDGER_COLUMNS - headers
    fail_global("ledger_schema_invalid", "missing required columns: #{missing.join(", ")}") unless missing.empty?

    index = {}
    rows.each_with_index do |row, index_zero|
      normalized = normalize_row(row.to_h)
      line = index_zero + 2
      validate_ledger_row(normalized, line)
      key = ledger_key(normalized["repo"], normalized["path"])
      if index.key?(key)
        add_failure(normalized["repo"], normalized["path"], "duplicate_ledger_row", "duplicate ledger row for #{key}")
      else
        index[key] = normalized.merge("__line" => line)
      end
    end

    { "path" => path, "rows" => rows, "index" => index }
  rescue CSV::MalformedCSVError => error
    fail_global("ledger_invalid_csv", "#{path}: #{error.message}")
    { "path" => path, "rows" => [], "index" => {} }
  end

  def load_source_truth
    path = first_existing([
      File.join(@workspace_root, "docs", "architecture", "source-truth.md"),
      File.join(@workspace_root, "architecture", "source-truth.md")
    ])
    fail_global("source_truth_missing", "missing docs/architecture/source-truth.md under #{@workspace_root}") unless path

    File.exist?(path) ? File.read(path) : ""
  end

  def selected_repos(manifest)
    repos = Array(manifest["repositories"]).reject { |repo| repo["archived"] == true }
    filters = Array(options[:repos]).map(&:to_s)
    repos = repos.select { |repo| filters.include?(repo["name"].to_s) } unless filters.empty?

    missing_filters = filters - repos.map { |repo| repo["name"].to_s }
    missing_filters.each do |name|
      add_failure(name, nil, "repo_not_active_in_manifest", "#{name} is not an active repo in #{manifest["__path"]}")
    end
    repos
  end

  def bootstrap_remote_manifest
    return if first_existing([
      File.join(@workspace_root, ".github-repo", "repo-manifest.yaml"),
      File.join(@workspace_root, ".github", "repo-manifest.yaml"),
      File.join(@workspace_root, "repo-manifest.yaml")
    ])

    ensure_remote_repo(".github")
  end

  def ensure_remote_repos(manifest, selected)
    repos_by_name = Array(manifest["repositories"]).to_h { |repo| [repo["name"].to_s, repo] }
    names = (%w[.github docs dev-orchestration] + selected.map { |repo| repo.fetch("name") }).uniq
    names.each do |name|
      repo = repos_by_name[name]
      if repo.nil?
        add_failure(name, nil, "support_repo_missing_from_manifest", "#{name} is required for remote docs truth but is missing from #{manifest["__path"]}")
        next
      end
      next if repo["archived"] == true

      ensure_remote_repo(name)
    end
  end

  def ensure_remote_repo(name)
    local = local_repo_name(name)
    path = File.join(@workspace_root, local)
    return true if File.directory?(File.join(path, ".git")) && fetch_remote_repo(path, name)

    clone_remote_repo(path, name)
  end

  def clone_remote_repo(path, name)
    FileUtils.mkdir_p(File.dirname(path))
    url = github_url(name)
    stdout, stderr, status = Open3.capture3("git", "clone", "--depth", "1", url, path)
    record_command("git clone #{redact_url(url)} #{path}", status, stdout, stderr)
    add_failure(name, nil, "remote_clone_failed", redact_text(stderr)) unless status.success?
    status.success?
  end

  def fetch_remote_repo(path, name)
    stdout, stderr, status = Open3.capture3("git", "-C", path, "fetch", "--depth", "1", "origin", "main")
    record_command("git -C #{path} fetch --depth 1 origin main", status, stdout, stderr)
    unless status.success?
      add_failure(name, nil, "remote_fetch_failed", redact_text(stderr))
      return false
    end

    stdout, stderr, status = Open3.capture3("git", "-C", path, "checkout", "--detach", "origin/main")
    record_command("git -C #{path} checkout --detach origin/main", status, stdout, stderr)
    add_failure(name, nil, "remote_checkout_failed", redact_text(stderr)) unless status.success?
    status.success?
  end

  def evaluate_repo(repo, manifest, ledger, source_truth)
    name = repo.fetch("name")
    path = repo_path(name)
    ignored_paths = repo_ignored_markdown_paths(name, path)
    tracked = tracked_markdown(path, ignored_paths)
    rows = ledger.fetch("index").select { |key, _row| key.start_with?("#{name}/") }
    report = {
      "path" => path,
      "tracked_markdown_count" => tracked.length,
      "ledger_row_count" => rows.length,
      "status" => "PASS"
    }
    @repo_reports[name] = report

    unless File.directory?(path)
      add_failure(name, nil, "repo_checkout_missing", "missing local checkout at #{path}")
      report["status"] = "FAIL"
      return
    end

    markdown_set = tracked.to_h { |relative_path| [relative_path, true] }
    tracked.each do |relative_path|
      row = ledger.fetch("index")[ledger_key(name, relative_path)]
      if row.nil?
        add_failure(name, relative_path, "missing_ledger_row", "tracked markdown is not in #{ledger["path"]}")
        next
      end
      evaluate_markdown_file(name, path, relative_path, row, manifest, source_truth)
    end

    rows.each_value do |row|
      next if markdown_set[row["path"]]
      next if ignored_markdown_path?(row["path"], ignored_paths)

      if row["status"] == "delete"
        next
      elsif row["status"] == "fix"
        add_failure(name, row["path"], "ledger_fix_status", "ledger status=fix cannot remain under enforcement")
      else
        add_failure(name, row["path"], "ledger_path_not_tracked", "ledger row points at markdown not tracked in #{name}")
      end
    end

    evaluate_changed_source_refs(name, path, ledger) if options[:changed_base]
    report["status"] = repo_failed?(name) ? "FAIL" : "PASS"
  end

  def evaluate_markdown_file(repo, repo_root, relative_path, row, manifest, _source_truth)
    status = row["status"]
    full_path = File.join(repo_root, relative_path)
    content = File.read(full_path)

    if status == "fix"
      add_failure(repo, relative_path, "ledger_fix_status", "ledger status=fix cannot remain under enforcement")
    elsif status == "delete"
      add_failure(repo, relative_path, "delete_status_file_still_tracked", "status=delete rows must be removed from the repo before enforcement")
      return
    elsif !ALLOWED_STATUSES.include?(status)
      add_failure(repo, relative_path, "invalid_ledger_status", "invalid status #{status.inspect}")
    end

    if status == "generated"
      evaluate_truth_gate(repo, repo_root, relative_path, row)
    end

    if archive_path?(relative_path) && status != "archive"
      add_failure(repo, relative_path, "archive_path_not_classified_archive", "archive-path markdown must have status=archive")
    end

    if status == "archive"
      superseded = row["superseded_by"].to_s.strip
      notes = row["notes"].to_s
      if superseded.empty? && !notes.match?(NO_CURRENT_SOURCE_WORDING)
        add_failure(repo, relative_path, "archive_missing_superseded_by", "archive rows need superseded_by or an explicit no-current-source note")
      end
      return
    end

    BANNED_STALE_PATTERNS.each do |pattern, label|
      next if label.start_with?("retired ") && content.match?(ARCHIVE_WORDING)

      add_failure(repo, relative_path, "banned_stale_string", "#{label}: #{pattern.source}") if content.match?(pattern)
    end

    stale_repo_refs(content, manifest).each do |stale_repo|
      next if content.match?(ARCHIVE_WORDING)

      add_failure(repo, relative_path, "stale_repo_reference", "mentions deleted/archived repo #{stale_repo} without archive/superseded wording")
    end

    claim_labels = public_claims(content)
    if active_status?(status) && public_truth_surface?(row, claim_labels)
      refs = split_refs(row["source_refs"])
      if refs.empty?
        add_failure(repo, relative_path, "public_claim_missing_source_refs", "public claim surface requires source_refs")
      elsif claim_labels.any? && refs.none? { |ref| source_owned_ref?(ref) }
        add_failure(repo, relative_path, "public_claim_missing_source_owned_refs", "public #{claim_labels.uniq.join("/")} claim requires source-owned evidence refs")
      end
    end
  end

  def evaluate_truth_gate(repo, repo_root, relative_path, row)
    command = row["truth_gate"].to_s.strip
    if command.empty?
      add_failure(repo, relative_path, "generated_missing_truth_gate", "status=generated requires truth_gate")
      return
    end

    stdout, stderr, status = Open3.capture3(
      { "MINDBURN_WORKSPACE_ROOT" => @workspace_root },
      "sh",
      "-c",
      command,
      chdir: repo_root
    )
    record_command("#{repo}: #{command}", status, stdout, stderr)
    return if status.success?

    add_failure(repo, relative_path, "generated_truth_gate_failed", "truth_gate failed: #{command}\n#{stderr.lines.last(10).join.strip}")
  rescue SystemCallError => error
    add_failure(repo, relative_path, "generated_truth_gate_failed", error.message)
  end

  def evaluate_changed_source_refs(repo, repo_root, ledger)
    base = options[:changed_base].to_s
    stdout, stderr, status = Open3.capture3("git", "-C", repo_root, "diff", "--name-only", "#{base}...HEAD")
    record_command("git -C #{repo_root} diff --name-only #{base}...HEAD", status, stdout, stderr)
    unless status.success?
      add_failure(repo, nil, "changed_base_diff_failed", stderr.strip)
      return
    end

    changed = stdout.lines.map(&:strip).reject(&:empty?)
    source_changes = changed.select { |path| source_change?(path) }
    return if source_changes.empty?

    docs_or_ledger_changed = changed.any? { |path| markdown_path?(path) || path == "audit/markdown-estate-ledger.csv" || path == "docs/audit/markdown-estate-ledger.csv" }
    return if docs_or_ledger_changed

    active_rows = ledger.fetch("index").values.select { |row| row["repo"] == repo && active_status?(row["status"]) }
    source_changes.each do |changed_path|
      refs = active_rows.select { |row| row_refs_changed_path?(row, changed_path) }
      next if refs.empty?

      add_failure(
        repo,
        changed_path,
        "referenced_source_changed_without_doc_update",
        "source file is referenced by active docs but this PR did not update markdown or the ledger"
      )
    end
  end

  def tracked_markdown(repo_root, ignored_paths = [])
    return [] unless File.directory?(repo_root)

    stdout, stderr, status = Open3.capture3("git", "-C", repo_root, "ls-files", "-z", "--", "*.md", "*.mdx")
    record_command("git -C #{repo_root} ls-files markdown", status, stdout, stderr)
    unless status.success?
      add_failure(File.basename(repo_root), nil, "git_ls_files_failed", stderr.strip)
      return []
    end

    stdout.split("\0").select { |path| markdown_path?(path) && !ignored_markdown_path?(path, ignored_paths) }.sort
  end

  def stale_repo_refs(content, manifest)
    deleted = Array(manifest.dig("inventory_summary", "deleted_repositories"))
    archived = Array(manifest["repositories"]).select { |repo| repo["archived"] == true }.map { |repo| repo["name"].to_s }
    (deleted + archived).uniq.select do |name|
      next false if name.empty?

      content.match?(/(?<![\w.-])#{Regexp.escape(name)}(?![\w.-])/)
    end
  end

  def public_claims(content)
    PUBLIC_CLAIM_PATTERNS.filter_map { |pattern, label| label if content.match?(pattern) }
  end

  def public_truth_surface?(row, claim_labels)
    truthy?(row["public_surface"]) || claim_labels.any?
  end

  def source_owned_ref?(ref)
    clean = ref.to_s.strip
    return false if clean.empty?
    return false if clean.match?(/\.mdx?\z/i)
    return false if clean.match?(/\A(?:docs|doc|audit)\//i)

    clean.match?(SOURCE_OWNED_REF)
  end

  def row_refs_changed_path?(row, changed_path)
    split_refs(row["source_refs"]).any? do |ref|
      ref_repo, ref_path = split_repo_ref(row["repo"], ref)
      next false unless ref_repo == row["repo"]

      changed_path == ref_path || changed_path.start_with?("#{ref_path.chomp("/")}/")
    end
  end

  def source_change?(path)
    return false if markdown_path?(path)

    SOURCE_CHANGE_EXTENSIONS.include?(File.extname(path)) || SOURCE_CHANGE_PATHS.any? { |pattern| path.match?(pattern) }
  end

  def validate_ledger_row(row, line)
    repo = row["repo"]
    path = row["path"]
    status = row["status"]
    add_failure(repo, path, "ledger_missing_repo", "line #{line}: repo is required") if repo.empty?
    add_failure(repo, path, "ledger_missing_path", "line #{line}: path is required") if path.empty?
    add_failure(repo, path, "ledger_invalid_status", "line #{line}: status must be one of #{ALLOWED_STATUSES.join(", ")}") unless ALLOWED_STATUSES.include?(status)
    add_failure(repo, path, "ledger_missing_owner", "line #{line}: owner is required") if row["owner"].empty?
    add_failure(repo, path, "ledger_missing_truth_kind", "line #{line}: truth_kind is required") if row["truth_kind"].empty?
  end

  def normalize_row(row)
    row.transform_keys(&:to_s).transform_values { |value| value.to_s.strip }.tap do |normalized|
      normalized["status"] = normalized["status"].downcase
    end
  end

  def split_refs(value)
    value.to_s.split(/[;,\n|]+/).map(&:strip).reject(&:empty?)
  end

  def split_repo_ref(default_repo, ref)
    clean = ref.to_s.strip
    if clean.include?(":") && clean.split(":", 2).first.match?(/\A[\w.-]+\z/)
      clean.split(":", 2)
    else
      [default_repo, clean]
    end
  end

  def first_existing(paths)
    paths.find { |path| File.exist?(path) }
  end

  def repo_path(name)
    File.join(@workspace_root, local_repo_name(name))
  end

  def local_repo_name(name)
    MANIFEST_LOCAL_ALIASES.fetch(name.to_s, name.to_s)
  end

  def ledger_key(repo, path)
    "#{repo}/#{path}"
  end

  def markdown_path?(path)
    path.end_with?(".md", ".mdx")
  end

  def repo_ignored_markdown_paths(repo_name, repo_root)
    config_path = File.join(repo_root, DOCS_TRUTH_CONFIG)
    return [] unless File.exist?(config_path)

    raw = YAML.safe_load(File.read(config_path), aliases: false) || {}
    ignored = Array(raw["ignored_paths"]).map(&:to_s).map(&:strip).reject(&:empty?)
    ignored.each do |pattern|
      next unless pattern.start_with?("../") || pattern.include?("/../")

      add_failure(repo_name, DOCS_TRUTH_CONFIG, "docs_truth_ignore_invalid", "ignored_paths cannot escape the repo: #{pattern}")
    end
    ignored
  rescue Psych::Exception => error
    add_failure(repo_name, DOCS_TRUTH_CONFIG, "docs_truth_config_invalid", error.message)
    []
  end

  def ignored_markdown_path?(path, ignored_paths = [])
    return true if IGNORED_MARKDOWN_PATHS.any? { |pattern| path.match?(pattern) }

    ignored_paths.any? { |pattern| ignored_by_config_pattern?(path, pattern) }
  end

  def ignored_by_config_pattern?(path, pattern)
    clean = pattern.sub(%r{\A/+}, "")
    if clean.end_with?("/")
      path.start_with?(clean)
    elsif clean.match?(/[*?\[]/)
      File.fnmatch?(clean, path, File::FNM_EXTGLOB)
    else
      path == clean
    end
  end

  def archive_path?(path)
    path.match?(%r{\Aarchive/}) || path.match?(%r{/archive/})
  end

  def active_status?(status)
    %w[active generated].include?(status)
  end

  def truthy?(value)
    %w[1 true yes y public].include?(value.to_s.strip.downcase)
  end

  def github_url(name)
    token = ENV["MINDBURN_ORG_READ_TOKEN"].to_s.strip
    repo_name = name == ".github" ? ".github" : name
    return "https://github.com/Mindburn-Labs/#{repo_name}.git" if token.empty?

    "https://x-access-token:#{token}@github.com/Mindburn-Labs/#{repo_name}.git"
  end

  def redact_url(url)
    url.gsub(%r{https://x-access-token:[^@]+@github\.com}, "https://x-access-token:[REDACTED]@github.com")
  end

  def redact_text(text)
    text.to_s.gsub(%r{https://x-access-token:[^@]+@github\.com}, "https://x-access-token:[REDACTED]@github.com")
  end

  def record_command(command, status, stdout, stderr)
    @commands << {
      "command" => command,
      "exit_status" => status.exitstatus,
      "success" => status.success?,
      "stdout_tail" => stdout.lines.last(10).join.strip,
      "stderr_tail" => redact_text(stderr.lines.last(10).join.strip)
    }
  end

  def add_failure(repo, path, code, message)
    @failures << {
      "repo" => repo,
      "path" => path,
      "code" => code,
      "message" => message
    }
  end

  def fail_global(code, message)
    add_failure(nil, nil, code, message)
  end

  def repo_failed?(repo)
    @failures.any? { |failure| failure["repo"] == repo }
  end

  def write_report(report)
    path = options[:report].to_s
    return if path.empty?

    FileUtils.mkdir_p(File.dirname(File.expand_path(path)))
    File.write(path, JSON.pretty_generate(report) + "\n")
  end
end

def parse_options(argv)
  options = {
    mode: "local",
    workspace_root: Dir.pwd,
    repos: [],
    changed_base: nil,
    report: nil,
    report_only: false,
    selftest: false
  }

  OptionParser.new do |parser|
    parser.banner = "Usage: docs-truth-org.rb [options]"
    parser.on("--mode MODE", "local or remote") { |value| options[:mode] = value }
    parser.on("--workspace-root PATH", "workspace root containing .github-repo, docs, and repos") { |value| options[:workspace_root] = value }
    parser.on("--repo NAME", "repo to check; repeatable") { |value| options[:repos] << value }
    parser.on("--changed-base REF", "base ref for PR source/doc drift checks") { |value| options[:changed_base] = value }
    parser.on("--report PATH", "write JSON report") { |value| options[:report] = value }
    parser.on("--report-only", "write/report failures but exit 0") { options[:report_only] = true }
    parser.on("--selftest", "run fixture tests") { options[:selftest] = true }
  end.parse!(argv)

  unless %w[local remote].include?(options[:mode])
    warn "--mode must be local or remote"
    exit 2
  end

  options
end

def run_git_fixture(repo_root, *args)
  stdout, stderr, status = Open3.capture3("git", *args, chdir: repo_root)
  raise "git #{args.join(" ")} failed: #{stderr}" unless status.success?

  stdout
end

def write_fixture_workspace(root, ledger_rows:, doc_content:, doc_path: "README.md", repo: "app", deleted: [], archived: [], docs_truth_config: nil)
  github_root = File.join(root, ".github-repo")
  docs_root = File.join(root, "docs")
  repo_root = File.join(root, repo == ".github" ? ".github-repo" : repo)
  FileUtils.mkdir_p(File.join(github_root))
  FileUtils.mkdir_p(File.join(docs_root, "audit"))
  FileUtils.mkdir_p(File.join(docs_root, "architecture"))
  FileUtils.mkdir_p(File.dirname(File.join(repo_root, doc_path)))

  repositories = ([repo] + archived).uniq.map do |name|
    { "name" => name, "visibility" => "private", "archived" => archived.include?(name) }
  end
  manifest = {
    "organization" => "Mindburn-Labs",
    "inventory_summary" => { "deleted_repositories" => deleted },
    "repositories" => repositories
  }
  File.write(File.join(github_root, "repo-manifest.yaml"), manifest.to_yaml)
  File.write(File.join(docs_root, "architecture", "source-truth.md"), "# Source Truth\n")
  File.write(File.join(repo_root, DOCS_TRUTH_CONFIG), docs_truth_config.to_yaml) if docs_truth_config

  CSV.open(File.join(docs_root, "audit", "markdown-estate-ledger.csv"), "w") do |csv|
    csv << REQUIRED_LEDGER_COLUMNS
    ledger_rows.each { |row| csv << REQUIRED_LEDGER_COLUMNS.map { |key| row.fetch(key, "") } }
  end

  run_git_fixture(repo_root, "init", "-q")
  File.write(File.join(repo_root, doc_path), doc_content)
  run_git_fixture(repo_root, "add", ".")
  repo_root
end

def assert_selftest(name)
  yield
  puts "PASS #{name}"
rescue StandardError => error
  warn "FAIL #{name}: #{error.message}"
  exit 1
end

def evaluate_fixture(root, repo: "app")
  DocsTruthGate.new(mode: "local", workspace_root: root, repos: [repo], report: nil).evaluate
end

def run_selftest
  assert_selftest("missing ledger row fails") do
    Dir.mktmpdir do |root|
      write_fixture_workspace(root, ledger_rows: [], doc_content: "# App\n", repo: "app")
      report = evaluate_fixture(root)
      raise "expected missing_ledger_row" unless report["failures"].any? { |failure| failure["code"] == "missing_ledger_row" }
    end
  end

  assert_selftest("repo docs-truth ignore skips generated reports") do
    Dir.mktmpdir do |root|
      write_fixture_workspace(
        root,
        ledger_rows: [],
        doc_path: "REPORTS/001/REPORT.md",
        doc_content: "# Ephemeral test report\n",
        repo: "docs_for_team",
        docs_truth_config: { "ignored_paths" => ["REPORTS/"] }
      )
      report = evaluate_fixture(root, repo: "docs_for_team")
      raise "expected pass, got #{report["failures"].inspect}" unless report["failures"].empty?
      count = report.dig("repos", "docs_for_team", "tracked_markdown_count")
      raise "expected ignored markdown not to be tracked" unless count == 0
    end
  end

  assert_selftest("archive doc with stale terms passes") do
    Dir.mktmpdir do |root|
      row = {
        "repo" => "app",
        "path" => "archive/old.md",
        "status" => "archive",
        "owner" => "docs",
        "truth_kind" => "historical",
        "source_refs" => "",
        "truth_gate" => "",
        "public_surface" => "false",
        "superseded_by" => "README.md",
        "notes" => "historical only"
      }
      write_fixture_workspace(root, ledger_rows: [row], doc_path: "archive/old.md", doc_content: "app-docs-platform was retired.\n", repo: "app")
      report = evaluate_fixture(root)
      raise "expected pass, got #{report["failures"].inspect}" unless report["failures"].empty?
    end
  end

  assert_selftest("active doc with deleted repo reference fails") do
    Dir.mktmpdir do |root|
      row = {
        "repo" => "app",
        "path" => "README.md",
        "status" => "active",
        "owner" => "docs",
        "truth_kind" => "repo",
        "source_refs" => "app:src/main.ts",
        "truth_gate" => "",
        "public_surface" => "false",
        "superseded_by" => "",
        "notes" => ""
      }
      write_fixture_workspace(root, ledger_rows: [row], doc_content: "Uses old-repo for runtime work.\n", repo: "app", deleted: ["old-repo"])
      report = evaluate_fixture(root)
      raise "expected stale_repo_reference" unless report["failures"].any? { |failure| failure["code"] == "stale_repo_reference" }
    end
  end

  assert_selftest("generated doc with failing truth_gate fails") do
    Dir.mktmpdir do |root|
      row = {
        "repo" => "app",
        "path" => "README.md",
        "status" => "generated",
        "owner" => "docs",
        "truth_kind" => "generated",
        "source_refs" => "app:src/main.ts",
        "truth_gate" => "ruby -e 'exit 1'",
        "public_surface" => "false",
        "superseded_by" => "",
        "notes" => ""
      }
      write_fixture_workspace(root, ledger_rows: [row], doc_content: "# Generated\n", repo: "app")
      report = evaluate_fixture(root)
      raise "expected generated_truth_gate_failed" unless report["failures"].any? { |failure| failure["code"] == "generated_truth_gate_failed" }
    end
  end

  assert_selftest("public production claim without source refs fails") do
    Dir.mktmpdir do |root|
      row = {
        "repo" => "app",
        "path" => "README.md",
        "status" => "active",
        "owner" => "docs",
        "truth_kind" => "public",
        "source_refs" => "",
        "truth_gate" => "",
        "public_surface" => "true",
        "superseded_by" => "",
        "notes" => ""
      }
      write_fixture_workspace(root, ledger_rows: [row], doc_content: "Production-ready checkout for customers.\n", repo: "app")
      report = evaluate_fixture(root)
      raise "expected public_claim_missing_source_refs" unless report["failures"].any? { |failure| failure["code"] == "public_claim_missing_source_refs" }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = parse_options(ARGV)
  if options[:selftest]
    run_selftest
    exit 0
  end

  report = DocsTruthGate.new(options).evaluate
  puts JSON.pretty_generate(report.fetch("summary"))
  exit(report["failures"].empty? || options[:report_only] ? 0 : 1)
end
