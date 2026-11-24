require "http/server"
require "./chef-api"

class HTTP::Server::Context
  property chef_user : String?
end

module Chef
  class Auth
    class Middleware
      include HTTP::Handler

      TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
      AUTH_PREFIX      = "x-ops-authorization-"

      getter key_provider : String -> OpenSSL::PKey::RSA | String | Nil

      property clock_skew : Time::Span = Time::Span.new(minutes: 15)
      property only : Array(String) = [] of String
      property exclude : Array(String) = [] of String

      def initialize(&@key_provider : String -> OpenSSL::PKey::RSA | String | Nil)
      end

      def call(context : HTTP::Server::Context)
        return call_next(context) unless protect?(context.request.path)
        verify(context)
      end

      private def verify(context)
        headers = context.request.headers

        userid = headers["X-Ops-Userid"]?
        timestamp = headers["X-Ops-Timestamp"]?
        content_hash = headers["X-Ops-Content-Hash"]?

        return reject(context, "missing X-Ops-Userid header") unless userid
        return reject(context, "missing X-Ops-Timestamp header") unless timestamp
        return reject(context, "missing X-Ops-Content-Hash header") unless content_hash

        signature = x_ops_signature(headers)
        return reject(context, "missing X-Ops-Authorization headers") if signature.empty?

        unless sign_header_valid?(headers["X-Ops-Sign"]?)
          return reject(context, "unsupported X-Ops-Sign header")
        end

        signed_at = parse_timestamp(timestamp)
        return reject(context, "invalid X-Ops-Timestamp header") unless signed_at
        return reject(context, "stale X-Ops-Timestamp header") if (Time.utc - signed_at).abs > @clock_skew

        body = read_body(context)
        unless content_hash_matches?(body, content_hash)
          return reject(context, "X-Ops-Content-Hash does not match request body")
        end

        public_key = public_key_for(userid)
        return reject(context, "unknown user #{userid}") unless public_key

        canonical = Auth.new(userid, public_key).canonical_request(
          context.request.method, Auth.canonical_path(context.request.path),
          content_hash, timestamp
        )
        unless signature_valid?(public_key, canonical, signature)
          return reject(context, "invalid signature")
        end

        context.chef_user = userid
        call_next(context)
      end

      private def protect?(path)
        return false if matches?(@exclude, path)
        @only.empty? || matches?(@only, path)
      end

      private def matches?(patterns, path)
        patterns.any? do |pattern|
          path =~ /^#{Regex.escape(pattern).gsub("\\*", ".*")}$/
        end
      end

      private def x_ops_signature(headers)
        chunks = [] of Tuple(Int32, String)
        headers.each do |name, values|
          downcased = name.downcase
          next unless downcased.starts_with?(AUTH_PREFIX)
          number = downcased[AUTH_PREFIX.size..].to_i?
          next unless number
          values.each { |value| chunks << {number, value} }
        end
        chunks.sort_by(&.[0]).map(&.[1]).join
      end

      private def sign_header_valid?(value)
        return false unless value
        parts = value.split(";").map(&.strip)
        parts.includes?("algorithm=#{SIGN_ALGORITHM}") &&
          parts.includes?("version=#{SIGN_VERSION}")
      end

      private def parse_timestamp(value)
        Time.parse(value, TIMESTAMP_FORMAT, Time::Location::UTC)
      rescue Time::Format::Error
        nil
      end

      private def read_body(context)
        body = context.request.body.try(&.gets_to_end) || ""
        context.request.body = IO::Memory.new(body)
        body
      end

      private def content_hash_matches?(body, content_hash)
        Base64.strict_encode(OpenSSL::Digest.new(SIGN_ALGORITHM).update(body).final) == content_hash
      end

      private def public_key_for(userid)
        case key = @key_provider.call(userid)
        when OpenSSL::PKey::RSA then key
        when String
          OpenSSL::PKey::RSA.new(key)
        else nil
        end
      rescue OpenSSL::PKey::PKeyError
        nil
      end

      private def signature_valid?(public_key, canonical, signature)
        public_key.verify(OpenSSL::Digest.new(SIGN_ALGORITHM), Base64.decode(signature), canonical)
      rescue Base64::Error
        false
      end

      private def reject(context, reason)
        response = context.response
        response.status_code = 401
        response.headers["Content-Type"] = "application/json"
        response.print JSON.build { |json| json.object { json.field("error", reason) } }
        nil
      end
    end
  end
end
