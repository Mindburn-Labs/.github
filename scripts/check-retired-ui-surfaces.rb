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
deleted = Array(summary.fetch("deleted_repositories"))

retired_repos.each do |name|
  repo = repo_by_name[name]
  errors << "retired UI/design repo still present in active manifest repositories: #{name}" if repo
  errors << "retired UI/design repo missing from inventory_summary.deleted_repositories: #{name}" unless deleted.include?(name)
  errors << "retired UI/design repo must not remain archived after deletion: #{name}" if archived.include?(name)
end

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

puts "retired UI/design surfaces remain deleted"
