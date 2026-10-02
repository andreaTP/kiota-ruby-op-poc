# frozen_string_literal: true

require "digest"
require "openssl"
require "uri"

module OpenPayments
  # Signs requests the way Open Payments requires: RFC 9421 message signatures with Ed25519,
  # and an RFC 9530 Content-Digest for any body.
  module HttpSignature
    module_function

    def content_digest(body) = "sha-512=:#{[Digest::SHA512.digest(body)].pack('m0')}:"

    def signature_params(components, key_id:, created:)
      "(#{components.map { |c| "\"#{c}\"" }.join(' ')});created=#{created};keyid=\"#{key_id}\""
    end

    def signature_base(components, values, params)
      (components.map { |c| "\"#{c}\": #{values.fetch(c)}" } << "\"@signature-params\": #{params}").join("\n")
    end

    def sign_base(base, private_key) = [private_key.sign(nil, base)].pack("m0")

    # the "x" member of the key's JWK: its raw public key, base64url without padding
    def jwk_x(key) = [key.raw_public_key].pack("m0").tr("+/", "-_").delete("=")

    # the server rebuilds @target-uri from the request line, which always has a path
    def target_uri(url)
      uri = URI(url.to_s)
      uri.path = "/" if uri.path.empty?
      uri.to_s
    end

    # returns the headers to add: content-digest and content-length when there is a body, then the signature
    def headers_for(method:, url:, body:, key_id:, private_key:, content_type: nil, authorization: nil, created: Time.now.to_i, label: "sig1")
      added = {}
      values = { "@method" => method.to_s.upcase, "@target-uri" => target_uri(url) }
      components = ["@method", "@target-uri"]
      if authorization
        components << "authorization"
        values["authorization"] = authorization
      end
      if body && !body.empty?
        added["Content-Digest"] = values["content-digest"] = content_digest(body)
        added["Content-Length"] = values["content-length"] = body.bytesize.to_s
        values["content-type"] = content_type
        components.push("content-digest", "content-length", "content-type")
      end
      params = signature_params(components, key_id:, created:)
      added["Signature-Input"] = "#{label}=#{params}"
      added["Signature"] = "#{label}=:#{sign_base(signature_base(components, values, params), private_key)}:"
      added
    end
  end
end
