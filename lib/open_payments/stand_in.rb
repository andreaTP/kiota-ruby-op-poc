# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "openssl"
require "uri"
require "webrick"
require_relative "http_signature"

module OpenPayments
  # A local stand-in for the Interledger test environment, serving the wallets alice and bob. It checks
  # each request's GNAP token, Content-Digest and Ed25519 signature, answers with the payloads the Open
  # Payments spec documents, and approves an interactive grant by calling the finish uri, as a browser would.
  class StandIn
    KEY_ID = "stand-in-key"

    # Rafiki answers a key it cannot find with a 400, a status the auth spec does not declare
    class UnknownKey < StandardError
      def initialize(message = "could not determine client") = super
    end

    attr_reader :private_key, :requests, :failures, :verified

    # reject: a path whose requests are signed with a key the server cannot find, to see how errors surface
    def self.serve(**)
      stand_in = new(**)
      stand_in.start
      yield stand_in
    ensure
      stand_in&.stop
    end

    def initialize(reject: nil)
      @private_key = OpenSSL::PKey.generate_key("ED25519")
      @public_key = OpenSSL::PKey.read(@private_key.public_to_pem)
      @reject = reject
      @requests = []
      @failures = []
      @verified = 0
      @server = WEBrick::HTTPServer.new(Port: 0, BindAddress: "127.0.0.1", Logger: WEBrick::Log.new(File::NULL), AccessLog: [])
      @base = "http://127.0.0.1:#{@server.config[:Port]}"
      @server.mount_proc("/") { |req, res| handle(req, res) }
    end

    def start = @thread = Thread.new { @server.start }

    def stop
      @server.shutdown
      @thread&.join
    end

    def key_id = KEY_ID
    def sender = "#{@base}/alice"
    def receiver = "#{@base}/bob"

    private

    def handle(req, res)
      body = req.body.to_s
      json = body.empty? ? nil : JSON.parse(body)
      @requests << { method: req.request_method, path: req.path, authorization: req["Authorization"], json: }
      verify(req, body) unless req.path =~ %r{\A/(alice|bob)(/jwks\.json)?\z}
      status, payload = route(req, json)
      reply(res, status, payload)
    rescue StandardError => e
      @failures << "#{req.request_method} #{req.path}: #{e.message}"
      reply(res, e.is_a?(UnknownKey) ? 400 : 401, error: { code: "invalid_client", description: e.message })
    end

    def reply(res, status, payload)
      res.status = status
      res["Content-Type"] = "application/json"
      res.body = JSON.generate(payload)
    end

    def verify(req, body)
      token = expected_token(req.path)
      raise "expected #{token ? "GNAP #{token}" : 'no token'}, got #{req['Authorization'].inspect}" unless req["Authorization"] == (token && "GNAP #{token}")
      input = req["Signature-Input"] or raise "no Signature-Input"
      label, params = input.split("=", 2)
      raise UnknownKey if @reject == req.path || !params.include?(";keyid=\"#{KEY_ID}\"")

      components = params[/\A\(([^)]*)\)/, 1].scan(/"([^"]+)"/).flatten
      values = components.to_h do |c|
        value = case c
                when "@method" then req.request_method
                when "@target-uri" then "#{@base}#{req.unparsed_uri}"
                else req[c]
                end
        [c, value]
      end
      unless body.empty?
        raise "content-digest mismatch" unless req["Content-Digest"] == HttpSignature.content_digest(body)
        raise "unsigned body" unless (%w[content-digest content-length content-type] - components).empty?
      end
      signature = req["Signature"].to_s[/\A#{label}=:(.*):\z/, 1] or raise "no signature for #{label}"
      raise "bad signature" unless @public_key.verify(nil, signature.unpack1("m0"), HttpSignature.signature_base(components, values, params))

      @verified += 1
    end

    # a new grant request is signed but carries no token yet
    def expected_token(path)
      case path
      when %r{\A/auth/continue/} then "continue-1"
      when %r{\A/incoming-payments} then "incoming-payment-1"
      when %r{\A/quotes} then "quote-1"
      when %r{\A/outgoing-payments} then "outgoing-payment-1"
      end
    end

    def route(req, json)
      case [req.request_method, req.path]
      in ["GET", "/alice"] then [200, wallet("alice")]
      in ["GET", "/bob"] then [200, wallet("bob")]
      in ["GET", %r{/jwks\.json\z}] then [200, { keys: [{ kid: KEY_ID, x: HttpSignature.jwk_x(@private_key), alg: "EdDSA", kty: "OKP", crv: "Ed25519" }] }]
      in ["POST", "/auth"] then grant(json)
      in ["POST", "/auth/continue/c-1"]
        raise "wrong interact_ref" unless json["interact_ref"] == "ref-1"

        [200, { access_token: token("outgoing-payment-1", [{ type: "outgoing-payment", actions: %w[read create] }]),
                continue: continuation("continue-2") }]
      in ["POST", "/incoming-payments"]
        @incoming_amount = json["incomingAmount"]
        [201, incoming(received: 0, methods: [{ type: "ilp", ilpAddress: "test.bob", sharedSecret: "c2VjcmV0" }])]
      in ["GET", "/incoming-payments/ip-1"]
        @incoming_reads = (@incoming_reads || 0) + 1
        [200, incoming(received: Integer(@incoming_amount["value"]) / (@incoming_reads > 1 ? 1 : 2), methods: [])]
      in ["POST", "/quotes"]
        [201, { id: "#{@base}/quotes/q-1", walletAddress: json["walletAddress"], receiver: json["receiver"], method: "ilp",
                debitAmount: amount(debit), receiveAmount: @incoming_amount,
                createdAt: "2026-09-30T10:00:01.000Z", expiresAt: "2026-09-30T10:05:01.000Z" }]
      in ["POST", "/outgoing-payments"]
        raise "unknown quote" unless json["quoteId"] == "#{@base}/quotes/q-1"

        [201, outgoing(sent: 0)]
      in ["GET", "/outgoing-payments/op-1"]
        [200, outgoing(sent: debit)]
      end
    end

    def wallet(name)
      { id: "#{@base}/#{name}", publicName: name, assetCode: "USD", assetScale: 2, authServer: "#{@base}/auth", resourceServer: @base }
    end

    def amount(value) = { value: value.to_s, assetCode: "USD", assetScale: 2 }

    def debit = Integer(@incoming_amount["value"]) + 2

    def token(value, access) = { value:, manage: "#{@base}/auth/token/#{value}", expires_in: 600, access: }

    def continuation(value) = { access_token: { value: }, uri: "#{@base}/auth/continue/c-1", wait: 1 }

    def incoming(received:, methods:)
      { id: "#{@base}/incoming-payments/ip-1", walletAddress: receiver, completed: received == Integer(@incoming_amount["value"]),
        incomingAmount: @incoming_amount, receivedAmount: amount(received), methods:,
        createdAt: "2026-09-30T10:00:00.000Z", updatedAt: "2026-09-30T10:00:03.000Z" }
    end

    def outgoing(sent:)
      { id: "#{@base}/outgoing-payments/op-1", walletAddress: sender, quoteId: "#{@base}/quotes/q-1", failed: false,
        receiver: "#{@base}/incoming-payments/ip-1", receiveAmount: @incoming_amount, debitAmount: amount(debit), sentAmount: amount(sent),
        createdAt: "2026-09-30T10:00:02.000Z", updatedAt: "2026-09-30T10:00:02.000Z" }
    end

    def grant(json)
      access = json.dig("access_token", "access")
      finish = json.dig("interact", "finish")
      return [200, { access_token: token("#{access.first['type']}-1", access), continue: continuation("continue-0") }] unless finish

      hash = [Digest::SHA256.digest([finish["nonce"], "server-nonce", "ref-1", "#{@base}/auth"].join("\n"))].pack("m0")
      Thread.new { Net::HTTP.get(URI("#{finish['uri']}?#{URI.encode_www_form(hash:, interact_ref: 'ref-1')}")) }
      [200, { interact: { redirect: "#{@base}/approve/1", finish: "server-nonce" }, continue: continuation("continue-1") }]
    end
  end
end
