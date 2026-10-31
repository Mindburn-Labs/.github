SHELL := /usr/bin/env bash
REQUIRE_WORKSPACE_CONTEXT ?= 0

.PHONY: check setup test lint build agent-context

# CI runs `make check` (Mindburn-Labs/platform-actions ci.yml@v2.0.1).
check: test

setup:
	@command -v ruby >/dev/null
	@command -v python3 >/dev/null

test: lint
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'

lint:
	@ruby -e 'require "yaml"; require "date"; YAML.safe_load(File.read("repo-manifest.yaml"), permitted_classes: [Date, Time], aliases: true); puts "validated repo-manifest.yaml"'
	@ruby scripts/generate-repo-inventory.rb --check
	@ruby -e 'require "yaml"; YAML.safe_load(File.read("agent.yaml"), aliases: true); YAML.safe_load(File.read("catalog-info.yaml"), aliases: true); YAML.safe_load(File.read("observability/alerts.yaml"), aliases: true); YAML.safe_load(File.read("docs/tracker/issue-templates.yaml"), aliases: true); puts "validated baseline yaml"'
	@ruby -e 'require "yaml"; d = YAML.safe_load(File.read("docs/tracker/issue-templates.yaml"), aliases: true); t = d.fetch("templates"); abort("issue-form catalog must list 5 forms") unless t.size == 5; t.each { |x| %w[name form issue_type done_gate].each { |k| abort("catalog entry missing #{k}") unless x[k].to_s.length.positive? } }; puts "validated tracker issue-form catalog"'
	@ruby scripts/check-retired-ui-surfaces.rb
	@ruby -e 'require "yaml"; require "date"; %w[manifest-local-policy.yaml local-compatibility-policy.yaml].each { |path| YAML.safe_load(File.read(path), permitted_classes: [Date, Time], aliases: true) }; puts "validated ecosystem map policies"'
	@ruby -e 'require "yaml"; YAML.safe_load(File.read("agent.yaml"), aliases: true); YAML.safe_load(File.read("catalog-info.yaml"), aliases: true); YAML.safe_load(File.read("observability/alerts.yaml"), aliases: true); puts "validated baseline yaml"'
	@ruby scripts/check-org-rename-guard.rb
	@if [ -n "$$MINDBURN_WORKSPACE_ROOT" ] || [ "$(REQUIRE_WORKSPACE_CONTEXT)" = "1" ]; then \
		ruby scripts/generate-helm-ecosystem-map.rb --check; \
	else \
		echo "skipped HELM ecosystem map check: full Mindburn workspace context unavailable in repo-only CI"; \
	fi
	@ruby scripts/check-headless-ui-references.rb
	@test -f profile/README.md
	@test -f AGENTS.md
	@test -f SECURITY.md
	@test -f docs/radar/ai-security-competitor-watchlist.md
	@test -f docs/tracker/release-gate-contract.md

build: lint

agent-context: lint
