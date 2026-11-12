# frozen_string_literal: true

require "digest"
require "json"
require "openssl"
require "securerandom"
require "socket"
require "uri"
require "microsoft_kiota_abstractions"
require "microsoft_kiota_faraday"
require "microsoft_kiota_serialization_json"
require_relative "gnap_authentication_provider"

unless File.exist?(File.expand_path("generated/resource/resource_client.rb", __dir__))
  warn "lib/open_payments/generated is missing, running bin/generate"
  system(File.expand_path("../../bin/generate", __dir__), exception: true)
end
require_relative "generated/wallet_address/wallet_address_client"
require_relative "generated/auth/auth_client"
require_relative "generated/resource/resource_client"

module OpenPayments
  # The interledger/open-payments-example flow through the Kiota generated clients: read both wallets,
  # get grants, create an incoming payment and a quote, have the outgoing payment grant approved in the
  # browser, create the outgoing payment, then poll the incoming payment until it is paid in full.
  class Demo
    class Error < StandardError; end

    AuthModels = Auth::Models
    ResourceModels = Resource::Models

    def self.run(**) = new(**).run

    def initialize(key_id:, private_key:, sender:, receiver:, amount: "100", callback_host: "127.0.0.1", callback_port: 3344,
                   out: $stdout)
      @key_id = key_id
      @private_key = private_key.is_a?(OpenSSL::PKey::PKey) ? private_key : OpenSSL::PKey.read(private_key)
      @sender_url = sender
      @receiver_url = receiver
      @amount = amount.to_s
      @callback_host = callback_host
      @callback_port = callback_port
      @out = out
    end

    def run
      sender = step("read the sending wallet") { wallet(@sender_url).get.resume }
      receiver = step("read the receiving wallet") { wallet(@receiver_url).get.resume }
      [sender, receiver].each { |w| say "#{w.id}: #{w.asset_code}/#{w.asset_scale}, auth #{w.auth_server}, resource #{w.resource_server}" }
      step("find the developer key in the sending wallet's keys") { check_key(wallet(@sender_url).jwks_json.get.resume, sender) }
      client = client_of(sender)

      incoming_token = step("incoming payment grant") do
        access = AuthModels::AccessIncoming.new.tap do |a|
          a.type = AuthModels::AccessIncomingType[:IncomingPayment]
          a.actions = %i[Read Complete Create].map { |k| AuthModels::AccessIncomingActions[k] }
        end
        token_of(auth(receiver).post(grant_request(client, [access_item(access_incoming: access)])).resume)
      end

      incoming = step("create the incoming payment") do
        body = ResourceModels::CreateIncomingPaymentRequest.new.tap do |r|
          r.wallet_address = receiver.id
          r.incoming_amount = ResourceModels::Amount.new.tap do |a|
            a.value = @amount
            a.asset_code = receiver.asset_code
            a.asset_scale = receiver.asset_scale
          end
        end
        resource(receiver, incoming_token).incoming_payments.post(body).resume
      end
      say "incoming payment #{incoming.id}, #{incoming.incoming_amount.value} #{incoming.incoming_amount.asset_code}"

      quote_token = step("quote grant") do
        access = AuthModels::AccessQuote.new.tap do |a|
          a.type = AuthModels::AccessQuoteType[:Quote]
          a.actions = %i[Create Read].map { |k| AuthModels::AccessQuoteActions[k] }
        end
        token_of(auth(sender).post(grant_request(client, [access_item(access_quote: access)])).resume)
      end

      quote = step("create the quote") do
        body = Resource::Quotes::CreateQuoteRequest.new.tap do |r|
          r.create_quote_request_by_receiver = ResourceModels::CreateQuoteRequestByReceiver.new.tap do |q|
            q.wallet_address = sender.id
            q.receiver = incoming.id
            q.method = ResourceModels::PaymentMethod[:Ilp]
          end
        end
        resource(sender, quote_token).quotes.post(body).resume
      end
      say "quote #{quote.id}: debit #{quote.debit_amount.value}, receive #{quote.receive_amount.value}"

      # listen before asking for the grant, so the redirect cannot arrive first
      callback = TCPServer.new(@callback_host, @callback_port)
      finish_uri = "http://localhost:#{callback.addr[1]}/callback"
      nonce = SecureRandom.hex(16)
      pending = step("interactive outgoing payment grant") do
        access = AuthModels::AccessOutgoing.new.tap do |a|
          a.type = AuthModels::AccessOutgoingType[:OutgoingPayment]
          a.actions = %i[Read Create].map { |k| AuthModels::AccessOutgoingActions[k] }
          a.identifier = sender.id
          a.limits = AuthModels::LimitsOutgoing.new.tap do |l|
            l.limits_outgoing_debit_amount = AuthModels::LimitsOutgoingDebitAmount.new.tap { |d| d.debit_amount = auth_amount(quote.debit_amount) }
          end
        end
        interact = AuthModels::InteractRequest.new.tap do |i|
          i.start = [AuthModels::InteractRequestStart[:Redirect]]
          i.finish = AuthModels::InteractRequestFinish.new.tap do |f|
            f.method = AuthModels::InteractRequestFinishMethod[:Redirect]
            f.uri = finish_uri
            f.nonce = nonce
          end
        end
        response = auth(sender).post(grant_request(client, [access_item(access_outgoing: access)], interact)).resume
        response.post_response_member1&.interact&.redirect or raise Error, "expected an interaction, got an access token"
        response.post_response_member1
      end

      say "\nApprove the payment in the browser:\n\n  #{pending.interact.redirect}\n\nWaiting on #{finish_uri} ..."
      query = redirect_query(callback)
      interact_ref = query.fetch("interact_ref") { raise Error, "the approval came back without an interact_ref: #{query}" }
      # the grant endpoint, as Rafiki hashes it: the authServer the wallet publishes, unchanged
      expected_hash = [Digest::SHA256.digest([nonce, pending.interact.finish, interact_ref, sender.auth_server].join("\n"))].pack("m0")
      say "interaction hash #{query['hash'] == expected_hash ? 'verified' : "not verified (got #{query['hash']})"}"

      outgoing_token = step("continue the grant") do
        body = AuthModels::ContinuationRequest.new.tap { |c| c.interact_ref = interact_ref }
        response = auth(sender, pending.continue.access_token.value)
                   .continue.by_id(last_segment(pending.continue.uri)).with_url(pending.continue.uri).post(body).resume
        response.access_token&.value or raise Error, "the continuation returned no access token"
      end

      outgoing = step("create the outgoing payment") do
        body = Resource::OutgoingPayments::CreateOutgoingPaymentRequest.new.tap do |r|
          r.create_outgoing_payment_request_from_quote = ResourceModels::CreateOutgoingPaymentRequestFromQuote.new.tap do |o|
            o.wallet_address = sender.id
            o.quote_id = quote.id
          end
        end
        resource(sender, outgoing_token).outgoing_payments.post(body).resume
      end
      say "outgoing payment #{outgoing.id}"

      status = step("read the outgoing payment") do
        resource(sender, outgoing_token).outgoing_payments.by_id(last_segment(outgoing.id)).get.resume
      end
      say "sent #{status.sent_amount&.value} of #{status.debit_amount&.value} #{status.debit_amount&.asset_code}, failed: #{status.failed.inspect}"

      10.times do |attempt|
        sleep 2 unless attempt.zero?
        received = step("read the incoming payment") do
          resource(receiver, incoming_token).incoming_payments.by_id(last_segment(incoming.id)).get.resume.incoming_payment_with_access_token
        end
        say "received #{received.received_amount&.value} of #{received.incoming_amount&.value} #{received.incoming_amount&.asset_code}, " \
            "completed: #{received.completed.inspect}"
        next unless received.received_amount&.value == received.incoming_amount&.value

        say "\npayment complete"
        return received
      end
      raise Error, "the incoming payment was not paid in full"
    ensure
      callback&.close
    end

    private

    def say(line) = @out.puts(line)

    # keeps the body of an error response, which Kiota drops when the spec declares no error for its status
    class KeepErrorBody < Faraday::Middleware
      def on_complete(env)
        options[:into].call(env.body) if env.status >= 400 && !env.body.to_s.empty?
      end
    end

    def step(title)
      say "\n== #{title}"
      @error_body = nil
      yield
    rescue MicrosoftKiotaAbstractions::ApiError => e
      detail = e.respond_to?(:error) && e.error ? "#{e.error.code}: #{e.error.description}" : @error_body || e.message
      raise Error, "#{title} failed: HTTP #{e.response_status_code} #{detail}"
    rescue Faraday::Error => e
      raise Error, "#{title} failed: #{e.message}"
    end

    def adapter(base_url, provider)
      http = MicrosoftKiotaFaraday::KiotaClientFactory.get_default_http_client
      http.builder.use KeepErrorBody, into: ->(body) { @error_body = body }
      MicrosoftKiotaFaraday::FaradayRequestAdapter.new(provider, nil, nil, http).tap { |a| a.set_base_url(base_url) }
    end

    def signer(access_token) = GnapAuthenticationProvider.new(key_id: @key_id, private_key: @private_key, access_token:)

    def wallet(url) = WalletAddress::WalletAddressClient.new(adapter(url, MicrosoftKiotaAbstractions::AnonymousAuthenticationProvider.new))

    # the auth server looks the key up the same way, but only answers "could not determine client"
    def check_key(key_set, wallet)
      key = key_set.keys&.find { |k| k.kid == @key_id }
      raise Error, "#{wallet.id} has no key #{@key_id}, its key ids are: #{key_set.keys&.map(&:kid)&.join(', ')}" unless key
      raise Error, "the private key does not match the public key #{@key_id} of #{wallet.id}" unless key.x == HttpSignature.jwk_x(@private_key)

      say "key #{@key_id} found"
    end

    def auth(wallet, access_token = nil) = Auth::AuthClient.new(adapter(wallet.auth_server, signer(access_token)))

    def resource(wallet, access_token) = Resource::ResourceClient.new(adapter(wallet.resource_server, signer(access_token)))

    def last_segment(url) = url.split("/").last

    def client_of(wallet)
      AuthModels::Client.new.tap do |c|
        c.client_wallet_address = AuthModels::ClientWalletAddress.new.tap { |w| w.wallet_address = wallet.id }
      end
    end

    def grant_request(client, access, interact = nil)
      Auth::GrantRequest.new.tap do |request|
        request.grant_request_with_access_token = AuthModels::GrantRequestWithAccessToken.new.tap do |g|
          g.access_token = AuthModels::GrantRequestWithAccessTokenAccessToken.new.tap { |t| t.access = access }
          g.client = client
          g.interact = interact
        end
      end
    end

    def access_item(**member) = AuthModels::AccessItem.new.tap { |item| member.each { |k, v| item.public_send("#{k}=", v) } }

    def auth_amount(from)
      AuthModels::Amount.new.tap do |a|
        a.value = from.value
        a.asset_code = from.asset_code
        a.asset_scale = from.asset_scale
      end
    end

    def token_of(response)
      response.post_response_member2&.access_token&.value or
        raise Error, "expected an access token, got #{JSON.generate(response.post_response_member1&.additional_data || {})}"
    end

    # the approval redirects the browser to the finish uri with the interaction reference and hash
    def redirect_query(server)
      loop do
        socket = server.accept
        target = socket.gets.to_s.split[1].to_s
        socket.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDone, you can close this tab.\n")
        socket.close
        # decode_uri_component keeps a "+" in the base64 hash
        query = URI(target).query.to_s.split("&").to_h { |pair| pair.split("=", 2).map { |s| URI.decode_uri_component(s.to_s) } }
        return query if query.key?("interact_ref") || query.key?("result")
      end
    end
  end
end
