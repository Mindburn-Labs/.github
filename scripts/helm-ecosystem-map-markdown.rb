# frozen_string_literal: true

module HelmEcosystemMapMarkdown
  module_function

  def group_for(name)
    case name
    when ".github"
      "GitHub Metadata"
    when "app-helm-console", "app-helm-docs", "app-mindburn-web"
      "Frontend / User Surfaces"
    when "factoryhub", "factoryhub2"
      "Factory Hub"
    when "app-docs-platform", "platform-design-system"
      "Archived UI / Design"
    when "pkg-mindburn-helm-ds", "pkg-mindburn-web-ds"
      "Design Systems"
    when "helm-ai-kernel", "helm-ai-enterprise", "helm-agent-integrations", "helm-rollout-evidence"
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
    when "docs", "docs-engineering-handbook", "docs_for_team", "dev-orchestration", "homebrew-tap"
      "Docs / Onboarding / Local Ops"
    when "ml-orggenome-compiler"
      "OrgGenome / ML"
    else
      "Other Manifest Repository"
    end
  end

  def expected_workspace_path_for(name, aliases, manifest_only_policy)
    alias_entry = aliases[name]
    return "alias `#{alias_entry.fetch("local_path")}`" if alias_entry
    return "not required locally" if manifest_only_policy.key?(name)

    "`#{name}`"
  end

  # Canon v1.1 D-17 naming: estate snapshots may still carry legacy
  # commercial-surface names; always render the canon name with the legacy alias.
  D17_SYSTEM_NAMES = {
    "Paid HELM AI Enterprise" => 'HELM AI OS (legacy name "Paid HELM AI Enterprise")',
    "Paid HELM AI" => 'HELM Cloud (legacy name "Paid HELM AI")'
  }.freeze

  def d17_system(name)
    D17_SYSTEM_NAMES.fetch(name, name)
  end

  def strict_classification(name, estate_entry)
    return "manifest-only; local estate entry absent" unless estate_entry

    kind = estate_entry["kind"]
    domain = estate_entry["domain"]
    system = d17_system(estate_entry["system"])
    lifecycle = estate_entry["lifecycle_state"]
    "`#{kind}`; #{domain} / #{system}; lifecycle `#{lifecycle}`"
  end

  def manifest_classification(repo, estate_entry)
    return strict_classification(repo.fetch("name"), estate_entry) unless repo["archived"] == true

    if estate_entry
      "`archived_repo`; #{estate_entry["domain"]} / #{d17_system(estate_entry["system"])}; lifecycle `archived`"
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

  def render(state)
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
        state.fetch(:legacy_snapshots) ? manifest_classification(repo, estate[name]) : "local classification unavailable; no snapshot supplied"
      ]
    end

    manifest_names = manifest_repos.map { |repo| repo.fetch("name") }
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
    lines << "generated_by: .github/scripts/generate-helm-ecosystem-map.rb"
    lines << "manifest_repository_count: #{manifest_summary.fetch("total_repositories")}"
    lines << "active_repository_count: #{manifest_summary.fetch("active_repositories")}"
    lines << "production_release_status: #{manifest_summary.fetch("production_release_status")}"
    lines << "source_of_truth:"
    lines << "  - .github/repo-manifest.yaml"
    lines << "  - .github/manifest-local-policy.yaml"
    lines << "  - .github/local-compatibility-policy.yaml"
    if state.fetch(:legacy_snapshots)
      lines << "  - production-readiness/estate/estate-inventory.json"
      lines << "  - production-readiness/estate/migration-index.json"
    end
    lines << "---"
    lines << ""
    lines << "# HELM Ecosystem Directory Map"
    lines << ""
    lines << "This file is generated. Do not edit it by hand."
    lines << ""
    lines << "> [!IMPORTANT]"
    lines << "> `$MINDBURN_WORKSPACE_ROOT` is a polyrepo workspace, not one git repository. `.github/repo-manifest.yaml` records GitHub repo existence, visibility, and archive status after live reconciliation. This committed map intentionally excludes temporal workstation directories."
    lines << ""
    lines << if state.fetch(:legacy_snapshots)
               "Local classification and migration rows below are legacy capture evidence supplied with `--legacy-snapshots`; they do not describe current workstation state."
             else
               "Local classification and migration snapshots were not supplied. Their absence is not evidence of an empty workstation or no migrations. Current read-only checks are owned by `dev-orchestration/estate-control-plane/bin/ecp`; `ecp` does not generate those legacy snapshots."
             end
    lines << ""
    lines << "## Current Manifest Truth"
    lines << ""
    lines.concat markdown_table(
      ["Field", "Value"],
      [
        ["GitHub organization", "`#{state.fetch(:manifest).fetch("organization")}`"],
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
    lines << "- Company Builder, Company OS, and HELM Network are product motions inside HELM. Pilot work becomes reusable HELM blueprints and evidence."
    lines << "- Local `*-wt-*` directories are task checkout directories by naming convention, not separate products or canonical repos; this map never enumerates them."
    lines << "- Compatibility/local-only directories are not GitHub repository truth unless they appear in `.github/repo-manifest.yaml`."
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
    lines << "For current local checkout findings, run `ruby dev-orchestration/estate-control-plane/bin/ecp check --root <workspace>`. An existing `production-readiness/estate/estate-inventory.json` is legacy capture evidence only; current `ecp` does not generate it. Neither artifact changes manifest repository truth."
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
    lines << (state.fetch(:legacy_snapshots) ? "The rows below are the legacy migration index, not a scan of local worktrees." : "Migration-index evidence is unavailable in this render; no migration inventory is asserted.")
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
        ["HELM product strategy, Company Builder, Company OS, Network, or pilot roles (canon §6.1.2: MS Realty and IronWrap — blueprint tracks; Tempora — arms-length evidence source)", "strategy canon `docs/ai/mindburn-labs-vision-paper.md` (v1.1; the former AI-2027 strategy and its 2026-07-24 extension are superseded — see their banners), then `docs/architecture/source-truth.md`"],
        ["Kernel verdicts, receipts, EvidencePacks, conformance", "`helm-ai-kernel`"],
        ['HELM AI OS (legacy name "Paid HELM AI Enterprise") backend/product logic', "`helm-ai-enterprise`, then `svc-helm-control-plane`"],
        ["Console UX", "`app-helm-console`; backend truth from `svc-helm-control-plane`"],
        ["Public docs", "`app-helm-docs`; source content and claims remain governed by their owning repos"],
        ["Public marketing site", "`app-mindburn-web`; public claims remain evidence-gated"],
        ["Connector contracts or packs", "`helm-ai-enterprise`, `contracts-catalog`, `svc-helm-certification`, `integration-helm`"],
        ["Production release state", "`integration-mindburn-platform`, `gitops-apps`, `gitops-platform`"],
        ["Infrastructure/server access", "`mindburn-infra`, `docs_for_team`"],
        ["Agent substrate/RLM support", "`platform-agent-substrate`, `svc-agent-sandbox-runner`"]
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
    lines << "- Validate with `ruby .github/scripts/generate-helm-ecosystem-map.rb --check` from a workspace containing the generated-map copies, or pass `--output <path>` for a scoped check."
    lines << "- Regenerate manifest-derived maps with `.github/scripts/refresh-helm-ecosystem-map.sh`. Use `--output <path>` for a scoped output; supply `--legacy-snapshots` only when both legacy capture files are available. Do not use a transient worktree list as committed topology."
    lines << "- Do not promote compatibility directories into canonical ownership without a manifest/source-truth change."
    lines << "- Do not promote local `*-wt-*` directories into product repos."
    lines << ""
    lines.join("\n")
  end
end
