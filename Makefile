SHELL := /usr/bin/env bash
REQUIRE_WORKSPACE_CONTEXT ?= 1

.PHONY: setup test lint build agent-context

setup:
	@command -v ruby >/dev/null

test: lint

lint:
	@ruby -e 'require "yaml"; require "date"; YAML.safe_load(File.read("repo-manifest.yaml"), permitted_classes: [Date, Time], aliases: true); puts "validated repo-manifest.yaml"'
	@ruby -e 'require "yaml"; require "date"; %w[manifest-local-policy.yaml local-compatibility-policy.yaml].each { |path| YAML.safe_load(File.read(path), permitted_classes: [Date, Time], aliases: true) }; puts "validated ecosystem map policies"'
	@ruby -e 'require "yaml"; YAML.safe_load(File.read("agent.yaml"), aliases: true); YAML.safe_load(File.read("catalog-info.yaml"), aliases: true); YAML.safe_load(File.read("observability/alerts.yaml"), aliases: true); puts "validated baseline yaml"'
	@if [ "$(REQUIRE_WORKSPACE_CONTEXT)" = "1" ]; then \
		ruby scripts/generate-helm-ecosystem-map.rb --check; \
	else \
		echo "skipped HELM ecosystem map check: full Mindburn workspace context unavailable in repo-only CI"; \
	fi
	@test -f profile/README.md
	@test -f AGENTS.md
	@test -f SECURITY.md
	@test -f docs/radar/ai-security-competitor-watchlist.md

build: lint

agent-context: lint
