# frozen_string_literal: true

require "stringio"
require_relative "../lib/open_payments/demo"
require_relative "../lib/open_payments/stand_in"

RSpec.describe OpenPayments::Demo do
  def run_against(stand_in, out = StringIO.new, **overrides)
    described_class.run(key_id: stand_in.key_id, private_key: stand_in.private_key, sender: stand_in.sender,
                        receiver: stand_in.receiver, amount: "250", callback_port: 0, out:, **overrides)
  end

  it "pays the receiver in full through the stand-in, every request signed" do
    out = StringIO.new
    OpenPayments::StandIn.serve do |stand_in|
      received = run_against(stand_in, out)

      expect(stand_in.failures).to be_empty
      expect(received.received_amount.value).to eq("250")
      expect(stand_in.requests.map { |r| "#{r[:method]} #{r[:path]}" }).to eq(
        ["GET /alice", "GET /bob", "GET /alice/jwks.json", "POST /auth", "POST /incoming-payments", "POST /auth", "POST /quotes",
         "POST /auth", "POST /auth/continue/c-1", "POST /outgoing-payments", "GET /outgoing-payments/op-1",
         "GET /incoming-payments/ip-1", "GET /incoming-payments/ip-1"]
      )
      expect(stand_in.verified).to eq(10)
      expect(stand_in.requests[3][:json]["access_token"]["access"])
        .to eq([{ "type" => "incoming-payment", "actions" => %w[read complete create] }])
    end
    expect(out.string).to include("interaction hash verified").and end_with("payment complete\n")
  end

  it "reports the step, the HTTP status and the Open Payments error code" do
    OpenPayments::StandIn.serve(reject: "/quotes") do |stand_in|
      expect { run_against(stand_in) }
        .to raise_error(described_class::Error, "create the quote failed: HTTP 400 invalid_client: could not determine client")
    end
  end

  it "reports the response body when the spec declares no error for the status" do
    OpenPayments::StandIn.serve(reject: "/auth") do |stand_in|
      expect { run_against(stand_in) }.to raise_error(
        described_class::Error,
        'incoming payment grant failed: HTTP 400 {"error":{"code":"invalid_client","description":"could not determine client"}}'
      )
    end
  end

  it "stops before the first grant when the sending wallet does not publish the key" do
    OpenPayments::StandIn.serve do |stand_in|
      expect { run_against(stand_in, key_id: "my-from") }
        .to raise_error(described_class::Error, "#{stand_in.sender} has no key my-from, its key ids are: stand-in-key")
      expect { run_against(stand_in, private_key: OpenSSL::PKey.generate_key("ED25519")) }
        .to raise_error(described_class::Error, "the private key does not match the public key stand-in-key of #{stand_in.sender}")
      expect(stand_in.requests.map { |r| r[:path] }).not_to include("/auth")
    end
  end
end
