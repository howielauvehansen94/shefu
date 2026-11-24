require "./spec_helper"
require "http/server"

class TerminalHandler
  include HTTP::Handler

  property called = false
  property body = ""

  def call(context)
    @called = true
    @body = context.request.body.try(&.gets_to_end) || ""
    context.response.status_code = 200
  end
end

def make_middleware(&key_provider : String -> OpenSSL::PKey::RSA | String | Nil)
  middleware = Chef::Auth::Middleware.new(&key_provider)
  terminal = TerminalHandler.new
  middleware.next = terminal
  {middleware, terminal}
end

def signed_headers(auth, method, path, body = "")
  headers = HTTP::Headers.new
  auth.sign!(headers, method, Chef::Auth.canonical_path(path), body)
  headers
end

def run(middleware, request)
  response = HTTP::Server::Response.new(IO::Memory.new)
  context = HTTP::Server::Context.new(request, response)
  middleware.call(context)
  context
end

describe Chef::Auth::Middleware do
  key = OpenSSL::PKey::RSA.new(2048)
  wrong_key = OpenSSL::PKey::RSA.new(2048)
  auth = Chef::Auth.new("test-client", key)

  it "authenticates a valid signed GET request" do
    middleware, terminal = make_middleware { |userid| userid == "test-client" ? key : nil }
    request = HTTP::Request.new("GET", "/organizations/org/nodes", signed_headers(auth, "GET", "/organizations/org/nodes"))
    context = run(middleware, request)

    context.chef_user.should eq("test-client")
    context.response.status_code.should eq(200)
    terminal.called.should be_true
  end

  it "authenticates a valid signed POST request and preserves the body" do
    middleware, terminal = make_middleware { |userid| key }
    body = %({"name":"web","run_list":["role[base]"]})
    request = HTTP::Request.new("POST", "/organizations/org/nodes",
      signed_headers(auth, "POST", "/organizations/org/nodes", body), body)
    context = run(middleware, request)

    context.chef_user.should eq("test-client")
    terminal.body.should eq(body)
  end

  it "rejects a request without X-Ops headers" do
    middleware, terminal = make_middleware { |userid| key }
    context = run(middleware, HTTP::Request.new("GET", "/nodes"))

    context.response.status_code.should eq(401)
    context.chef_user.should be_nil
    terminal.called.should be_false
  end

  it "rejects a signature made with the wrong key" do
    other_auth = Chef::Auth.new("test-client", wrong_key)
    middleware, terminal = make_middleware { |userid| key }
    request = HTTP::Request.new("GET", "/organizations/org/nodes",
      signed_headers(other_auth, "GET", "/organizations/org/nodes"))
    context = run(middleware, request)

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "rejects a tampered body (content hash mismatch)" do
    middleware, terminal = make_middleware { |userid| key }
    request = HTTP::Request.new("POST", "/organizations/org/nodes",
      signed_headers(auth, "POST", "/organizations/org/nodes", %({"name":"web"})),
      %({"name":"evil"}))
    context = run(middleware, request)

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "rejects a stale timestamp" do
    middleware, terminal = make_middleware { |userid| key }
    headers = signed_headers(auth, "GET", "/organizations/org/nodes")
    headers["X-Ops-Timestamp"] = (Time.utc - 20.minutes).to_s("%Y-%m-%dT%H:%M:%SZ")
    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", headers))

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "accepts an older timestamp within a custom clock skew" do
    middleware, terminal = make_middleware { |userid| key }
    middleware.clock_skew = Time::Span.new(minutes: 60)

    timestamp = (Time.utc - 30.minutes).to_s("%Y-%m-%dT%H:%M:%SZ")
    content_hash = Base64.strict_encode(OpenSSL::Digest.new("sha256").update("").final)
    canonical = auth.canonical_request("GET", "/organizations/org/nodes", content_hash, timestamp)
    headers = HTTP::Headers{
      "X-Ops-Sign"               => "algorithm=sha256;version=1.3",
      "X-Ops-Userid"             => "test-client",
      "X-Ops-Timestamp"          => timestamp,
      "X-Ops-Content-Hash"       => content_hash,
      "X-Ops-Server-API-Version" => "1",
      "X-Ops-Authorization-1"    => Base64.strict_encode(key.sign(OpenSSL::Digest.new("sha256"), canonical)),
    }

    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", headers))
    context.chef_user.should eq("test-client")
    terminal.called.should be_true
  end

  it "rejects an unknown user" do
    middleware, terminal = make_middleware { |userid| nil }
    request = HTTP::Request.new("GET", "/organizations/org/nodes",
      signed_headers(auth, "GET", "/organizations/org/nodes"))
    context = run(middleware, request)

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "accepts a public key provided as a PEM string" do
    middleware, terminal = make_middleware { |userid| key.public_key.to_pem }
    request = HTTP::Request.new("GET", "/organizations/org/nodes",
      signed_headers(auth, "GET", "/organizations/org/nodes"))
    context = run(middleware, request)

    context.chef_user.should eq("test-client")
    terminal.called.should be_true
  end

  it "rejects an unsupported X-Ops-Sign version" do
    middleware, terminal = make_middleware { |userid| key }
    headers = signed_headers(auth, "GET", "/organizations/org/nodes")
    headers["X-Ops-Sign"] = "algorithm=sha256;version=2.0"
    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", headers))

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "rejects an unparseable timestamp" do
    middleware, terminal = make_middleware { |userid| key }
    headers = signed_headers(auth, "GET", "/organizations/org/nodes")
    headers["X-Ops-Timestamp"] = "not-a-timestamp"
    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", headers))

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "rejects a signature that is not valid base64" do
    middleware, terminal = make_middleware { |userid| key }
    headers = signed_headers(auth, "GET", "/organizations/org/nodes")
    headers["X-Ops-Authorization-1"] = "!!!"
    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", headers))

    context.response.status_code.should eq(401)
    terminal.called.should be_false
  end

  it "authenticates headers sent with lowercased names" do
    middleware, terminal = make_middleware { |userid| key }
    downcased = HTTP::Headers.new
    signed_headers(auth, "GET", "/organizations/org/nodes").each do |name, values|
      values.each { |value| downcased.add(name.downcase, value) }
    end
    context = run(middleware, HTTP::Request.new("GET", "/organizations/org/nodes", downcased))

    context.chef_user.should eq("test-client")
    terminal.called.should be_true
  end

  it "skips authentication for excluded paths" do
    middleware, terminal = make_middleware { |userid| key }
    middleware.exclude = ["/health*"]
    context = run(middleware, HTTP::Request.new("GET", "/health/live"))

    context.response.status_code.should eq(200)
    terminal.called.should be_true
  end

  it "only authenticates paths matching the only filter" do
    middleware, terminal = make_middleware { |userid| key }
    middleware.only = ["/api/*"]

    passed = run(middleware, HTTP::Request.new("GET", "/public/info"))
    passed.response.status_code.should eq(200)
    terminal.called.should be_true

    blocked = run(middleware, HTTP::Request.new("GET", "/api/nodes"))
    blocked.response.status_code.should eq(401)
  end

  it "round-trips with Chef::Client over a real socket" do
    server = HTTP::Server.new([
      Chef::Auth::Middleware.new { |userid| userid == "integration-client" ? key : nil },
    ]) do |context|
      context.response.headers["Content-Type"] = "application/json"
      context.response.print %({"user":#{context.chef_user.to_json},"ok":true})
    end

    address = server.bind_unused_port
    spawn { server.listen }

    key_file = File.tempfile("chef_key") { |f| f.print(key.to_pem) }
    client = Chef::Client.new("http://#{address}", "integration-client", key_file.path)

    begin
      result = client.get("/organizations/org/nodes/web")
      result["user"].as_s.should eq("integration-client")
      result["ok"].as_bool.should be_true

      key_file2 = File.tempfile("chef_key") { |f| f.print(wrong_key.to_pem) }
      begin
        bad_client = Chef::Client.new("http://#{address}", "integration-client", key_file2.path)
        expect_raises(Chef::Error, "401") do
          bad_client.get("/organizations/org/nodes/web")
        end
      ensure
        key_file2.delete
      end
    ensure
      server.close
      key_file.delete
    end
  end
end
