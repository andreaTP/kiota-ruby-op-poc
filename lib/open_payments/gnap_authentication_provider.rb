# frozen_string_literal: true

require "microsoft_kiota_abstractions"
require_relative "http_signature"

module OpenPayments
  # Adds the GNAP access token when there is one, and signs every request with the client's key.
  class GnapAuthenticationProvider
    include MicrosoftKiotaAbstractions::AuthenticationProvider

    attr_accessor :access_token

    def initialize(key_id:, private_key:, access_token: nil)
      @key_id = key_id
      @private_key = private_key.is_a?(OpenSSL::PKey::PKey) ? private_key : OpenSSL::PKey.read(private_key)
      @access_token = access_token
    end

    def authenticate_request(request, _additional_properties = {})
      Fiber.new do
        authorization = @access_token && "GNAP #{@access_token}"
        request.headers.add("Authorization", authorization) if authorization
        HttpSignature.headers_for(method: request.http_method, url: request.uri, body: body_of(request),
                                  content_type: request.headers.get("Content-Type")&.first, authorization:,
                                  key_id: @key_id, private_key: @private_key)
                     .each { |name, value| request.headers.add(name, value) }
      end
    end

    private

    def body_of(request)
      content = request.content
      return content&.to_s unless content.respond_to?(:read)

      content.rewind
      content.read.tap { content.rewind }
    end
  end
end
