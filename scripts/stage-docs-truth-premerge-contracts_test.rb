#!/usr/bin/env ruby
# frozen_string_literal: true

require "csv"
require "minitest/autorun"
require "socket"
require "tmpdir"
require_relative "stage-docs-truth-premerge-contracts"

class StageDocsTruthPremergeContractsTest < Minitest::Test
  OWNER = "Mindburn-Labs"
  REPO = "helm-ai-kernel"
  PATH = "docs/new-guide.md"
  HEAD_SHA = "b5ecb899347bef73b793be48ee81e8c16e7d88fa"
  TODAY = Date.new(2026, 7, 16)

  class FakeClient
    attr_accessor :base_ref, :base_repo, :default_content, :file_status, :head_content, :head_path, :head_repo, :head_sha, :head_type, :pull_state

    def initialize
      @default_content = false
      @head_content = true
      @head_path = PATH
      @pull_state = "open"
      @file_status = "added"
      @base_ref = "main"
      @base_repo = "Mindburn-Labs/helm-ai-kernel"
      @head_repo = "Mindburn-Labs/helm-ai-kernel"
      @head_sha = HEAD_SHA
      @head_type = "file"
    end

    def repository(*) = {"default_branch" => "main"}

    def pull(*)
      {
        "state" => pull_state,
        "base" => {"ref" => base_ref, "repo" => {"full_name" => base_repo}},
        "head" => {"sha" => head_sha, "repo" => {"full_name" => head_repo}}
      }
    end

    def pull_files(*) = [{"filename" => PATH, "status" => file_status}]

    def content(*args)
      path = args[-2]
      ref = args[-1]
      present = ref == "main" ? default_content : head_content
      present ? {"type" => (ref == "main" ? "file" : head_type), "path" => (ref == "main" ? path : head_path)} : nil
    end
  end

  def setup
    @client = FakeClient.new
    @root = Dir.mktmpdir
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def row(notes: "pre-merge docs-truth contract for #{OWNER}/#{REPO}#568@#{HEAD_SHA} expires=2026-07-23; verified fixture", repo: REPO, path: PATH)
    CSV::Row.new(%w[repo path notes], [repo, path, notes])
  end

  def filter(candidate = row)
    DocsTruthPremergeContracts.filter(
      rows: CSV::Table.new([candidate]), root: @root, owner: OWNER, repo: REPO, client: @client, today: TODAY
    )
  end

  def test_stages_only_a_new_file_from_the_bound_open_pull_request
    kept, staged = filter
    assert_empty kept
    assert_equal ["#{REPO}:#{PATH} -> #{OWNER}/#{REPO}#568@#{HEAD_SHA}"], staged
  end

  def test_keeps_rows_without_an_exact_bound_marker
    kept, staged = filter(row(notes: "pre-merge docs-truth contract for Other/#{REPO}#568@#{HEAD_SHA} expires=2026-07-23"))
    assert_equal 1, kept.length
    assert_empty staged
  end

  def test_keeps_rows_owned_by_another_repository
    kept, staged = filter(row(repo: "docs"))
    assert_equal 1, kept.length
    assert_empty staged
  end

  def test_keeps_a_path_that_already_exists_on_the_default_branch
    @client.default_content = true
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_contract_for_a_closed_pull_request
    @client.pull_state = "closed"
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_path_not_added_by_the_pull_request
    @client.file_status = "modified"
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_contract_whose_head_does_not_contain_the_file
    @client.head_content = false
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_contract_whose_head_response_is_not_the_exact_file
    @client.head_type = "dir"
    assert_equal 1, filter.first.length
    @client.head_type = "file"
    @client.head_path = "docs/other.md"
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_contract_from_an_external_head_repository
    @client.head_repo = "attacker/helm-ai-kernel"
    assert_equal 1, filter.first.length
  end

  def test_keeps_a_contract_when_the_pull_request_head_moves
    @client.head_sha = "a" * 40
    assert_equal 1, filter.first.length
  end

  def test_keeps_malformed_expired_and_overlong_contracts
    missing_sha = "pre-merge docs-truth contract for #{OWNER}/#{REPO}#568 expires=2026-07-23"
    expired = "pre-merge docs-truth contract for #{OWNER}/#{REPO}#568@#{HEAD_SHA} expires=2026-07-15"
    too_long = "pre-merge docs-truth contract for #{OWNER}/#{REPO}#568@#{HEAD_SHA} expires=2026-07-24"
    trailing = "pre-merge docs-truth contract for #{OWNER}/#{REPO}#568@#{HEAD_SHA} expires=2026-07-23 trailing"
    [missing_sha, expired, too_long, trailing].each do |notes|
      assert_equal 1, filter(row(notes: notes)).first.length
    end
  end

  def test_keeps_a_contract_with_a_different_base_repository_or_branch
    @client.base_repo = "Other/helm-ai-kernel"
    assert_equal 1, filter.first.length
    @client.base_repo = "Mindburn-Labs/helm-ai-kernel"
    @client.base_ref = "release"
    assert_equal 1, filter.first.length
  end

  def test_keeps_unsafe_and_non_markdown_paths
    assert_equal 1, filter(row(path: "../outside.md")).first.length
    assert_equal 1, filter(row(path: "docs/payload.sh")).first.length
  end

  def test_keeps_a_file_present_in_the_checked_branch
    path = File.join(@root, "docs", "new-guide.md")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "present")
    assert_equal 1, filter.first.length
  end

  def test_api_errors_fail_the_staging_step_closed
    @client.define_singleton_method(:pull) { |*| raise "GitHub API 500" }
    error = assert_raises(RuntimeError) { filter }
    assert_equal "GitHub API 500", error.message
  end

  def test_real_http_client_sends_bearer_auth_and_encodes_path_segments
    response = '{"type":"file","path":"docs/Architecture Overview.md"}'
    result, request = capture_http_request(status: 200, body: response) do |api_base|
      client = DocsTruthPremergeContracts::GitHubClient.new(token: "sentinel-token", api_base: api_base)
      client.content(OWNER, REPO, "docs/Architecture Overview.md", HEAD_SHA)
    end
    assert_equal "docs/Architecture Overview.md", result["path"]
    assert_includes request.lines.first, "/docs/Architecture%20Overview.md?ref=#{HEAD_SHA}"
    authorization = request.lines.find { |line| line.downcase.start_with?(["author", "ization:"].join) }
    scheme, token = authorization.split(":", 2).last.strip.split(" ", 2)
    assert_equal "Bearer", scheme
    assert_equal "sentinel-token", token
  end

  def test_real_http_client_handles_not_found_and_fails_on_server_errors
    result, = capture_http_request(status: 404, body: '{"message":"Not Found"}') do |api_base|
      client = DocsTruthPremergeContracts::GitHubClient.new(token: "sentinel-token", api_base: api_base)
      client.content(OWNER, REPO, PATH, HEAD_SHA)
    end
    assert_nil result

    error = assert_raises(RuntimeError) do
      capture_http_request(status: 500, body: '{"message":"error"}') do |api_base|
        client = DocsTruthPremergeContracts::GitHubClient.new(token: "sentinel-token", api_base: api_base)
        client.repository(OWNER, REPO)
      end
    end
    assert_match(/GitHub API 500/, error.message)
  end

  def test_client_paginates_pull_files
    client_class = Class.new(DocsTruthPremergeContracts::GitHubClient) do
      attr_reader :requests

      def initialize
        @requests = []
      end

      private

      def get(_path, query)
        @requests << query
        query.fetch(:page) == 1 ? Array.new(100) { {"filename" => "docs/page-one.md"} } : [{"filename" => "docs/page-two.md"}]
      end
    end
    client = client_class.new
    files = client.pull_files(OWNER, REPO, 568)
    assert_equal 101, files.length
    assert_equal [1, 2], client.requests.map { |query| query.fetch(:page) }
  end

  private

  def capture_http_request(status:, body:)
    server = TCPServer.new("127.0.0.1", 0)
    request_thread = Thread.new do
      socket = server.accept
      request = +""
      request << socket.readpartial(1024) until request.include?("\r\n\r\n")
      reason = status == 200 ? "OK" : "Error"
      socket.write("HTTP/1.1 #{status} #{reason}\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
      socket.close
      request
    end
    result = yield("http://127.0.0.1:#{server.addr[1]}")
    [result, request_thread.value]
  ensure
    request_thread&.kill if request_thread&.alive?
    request_thread&.join
    server&.close
  end
end
