SHELL := /usr/bin/env bash

.PHONY: setup test lint build agent-context

setup:
	@command -v ruby >/dev/null

test: lint

lint:
	@ruby -e 'require "yaml"; require "date"; YAML.safe_load(File.read("repo-manifest.yaml"), permitted_classes: [Date, Time], aliases: true); puts "validated repo-manifest.yaml"'
	@ruby -e 'require "yaml"; YAML.safe_load(File.read("agent.yaml"), aliases: true); YAML.safe_load(File.read("catalog-info.yaml"), aliases: true); YAML.safe_load(File.read("observability/alerts.yaml"), aliases: true); puts "validated baseline yaml"'
	@test -f profile/README.md
	@test -f AGENTS.md
	@test -f SECURITY.md
	@test -f docs/radar/ai-security-competitor-watchlist.md

build: lint

agent-context: lint
