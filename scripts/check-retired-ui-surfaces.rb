#!/usr/bin/env ruby
# frozen_string_literal: true

require "date"
require "yaml"

manifest_path = File.expand_path("../repo-manifest.yaml", __dir__)
manifest = YAML.safe_load(
  File.read(manifest_path),
  permitted_classes: [Date, Time],
  aliases: true
)

retired_repos = %w[
  app-docs-platform
  app-helm-console
  app-mindburn-web
  platform-design-system
].freeze

errors = []
summary = manifest.fetch("inventory_summary")
repos = manifest.fetch("repositories")
repo_by_name = repos.to_h { |repo| [repo.fetch("name"), repo] }
archived = Array(summary.fetch("archived_repositories"))

retired_repos.each do |name|
  repo = repo_by_name[name]
  errors << "retired UI/design repo missing from manifest: #{name}" unless repo
  errors << "retired UI/design repo not marked archived in repositories: #{name}" if repo && repo["archived"] != true
  errors << "retired UI/design repo missing from inventory_summary.archived_repositories: #{name}" unless archived.include?(name)
end

active_retired = repos.select { |repo| retired_repos.include?(repo.fetch("name")) && repo["archived"] != true }.map { |repo| repo.fetch("name") }
errors << "retired UI/design repos are active: #{active_retired.join(", ")}" unless active_retired.empty?

actual_active_count = repos.count { |repo| repo["archived"] != true }
declared_active_count = summary.fetch("active_repositories")
if actual_active_count != declared_active_count
  errors << "active_repositories=#{declared_active_count} does not match non-archived repository count #{actual_active_count}"
end

unless summary.fetch("production_release_status") == "not_released"
  errors << "production_release_status must remain not_released during the headless UI reset"
end

if errors.any?
  warn errors.join("\n")
  exit 1
end

puts "retired UI/design surfaces remain archived"
