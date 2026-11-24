# shefu

A Crystal re-implementation of [Chef Infra server](https://docs.chef.io/server/)
authentication: API v1.3 signed-header authentication (request signing *and*
server-side verification) and API client.

Signs requests with an RSA key using the same wire format as
[mixlib-authentication](https://github.com/chef/mixlib-authentication) (the
`X-Ops-*` headers), so it works against any Chef Infra server or compatible
API.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  shefu:
    github: howielauvehansen94/shefu
```

## Usage

```crystal
require "shefu"

client = Shefu::Client.new(
  "https://chef.example.com/organizations/myorg",
  "my-client-name",
  "~/.chef/my-client.pem"
)

# GET /organizations/myorg/nodes
nodes = client.get("/nodes")

# POST with JSON body (Hash / NamedTuple / JSON::Any)
node = client.post("/nodes", {name: "web", run_list: ["role[base]"]})

# PUT /organizations/myorg/nodes/web with the updated node
client.put("/nodes/web", node)

# DELETE
client.delete("/nodes/web")

# Raw (non-JSON) response body, e.g. cookbook file contents
client.get_raw("/organizations/myorg/cookbooks/apache2/recipes/default.rb")

# Query strings are sent but excluded from the signature, as Chef requires
client.get("/nodes?name=web")
```

Non-2xx responses raise `Shefu::Error` with a `status` getter.

## Server-side verification (Kemal / HTTP::Handler)

`Shefu::Auth::Middleware` is the server-side counterpart: an `HTTP::Handler`
that verifies incoming v1.3 signed-header requests — the same checks a Chef
Infra server performs — and rejects them with `401` JSON. It drops into Kemal
via `add_handler` (or any Crystal `HTTP::Server` app):

```crystal
require "kemal"
require "shefu"

add_handler Shefu::Auth::Middleware.new do |userid|
  # Return the caller's public key for the X-Ops-Userid: an
  # OpenSSL::PKey::RSA, a PEM String, or nil to reject the user.
  KeyStore.public_key(userid)
end

get "/organizations/:org/nodes" do |env|
  env.shefu_user # the verified X-Ops-Userid, e.g. "test-client"
end
```

The middleware validates the required `X-Ops-*` headers, the `X-Ops-Sign`
algorithm/version, timestamp freshness (15 minutes by default), the body
content hash, and the RSA-SHA256 signature over the canonical request —
reusing the exact canonicalization from `Shefu::Auth`. The body is restored
after hashing, so Kemal's params/JSON parsing still works in routes.

Scope and tolerance are configurable:

```crystal
middleware = Shefu::Auth::Middleware.new { |userid| keys[userid]? }
middleware.clock_skew = 5.minutes
middleware.only = ["/api/*"]     # authenticate only these paths
middleware.exclude = ["/health"]  # never authenticate these (`*` crosses `/`)
add_handler middleware
```

### Signing only

If you only need the request-signing logic (e.g. for your own HTTP layer),
use `Shefu::Auth` directly:

```crystal
auth = Shefu::Auth.new("my-client-name", File.read("~/.chef/my-client.pem"))
auth.sign!(headers, "GET", "/organizations/myorg/nodes", "")
# headers now carries X-Ops-Sign, X-Ops-Userid, X-Ops-Timestamp,
# X-Ops-Content-Hash and the split X-Ops-Authorization-N signature headers
```

## SSL

`Shefu::Client` verifies TLS certificates by default; pass `verify_ssl: false`
as the fourth argument to disable verification.

## Development

```
shards install
crystal spec
```

## License

MIT — see [LICENSE](LICENSE).
