# frozen_string_literal: true

require_relative "../lib/open_payments/gnap_authentication_provider"

RSpec.describe OpenPayments::GnapAuthenticationProvider do
  let(:key) { OpenSSL::PKey.generate_key("ED25519") }

  def request_with(body: nil)
    request = MicrosoftKiotaAbstractions::RequestInformation.new
    request.url_template = "{+baseurl}/incoming-payments"
    request.path_parameters = { "baseurl" => "https://ilp.example" }
    request.http_method = :POST
    if body
      request.headers.try_add("Content-Type", "application/json")
      request.instance_variable_set(:@content, body)
    end
    request
  end

  it "adds the GNAP token and a signature that covers it and the body" do
    request = request_with(body: '{"a":1}')
    described_class.new(key_id: "k", private_key: key, access_token: "t").authenticate_request(request).resume

    expect(request.headers.get("Authorization")).to eq(["GNAP t"])
    expect(request.headers.get("Signature-Input").first).to include('"authorization" "content-digest" "content-length" "content-type"')
    base = "\"@method\": POST\n\"@target-uri\": https://ilp.example/incoming-payments\n\"authorization\": GNAP t\n" \
           "\"content-digest\": #{request.headers.get('Content-Digest').first}\n\"content-length\": 7\n\"content-type\": application/json\n" \
           "\"@signature-params\": #{request.headers.get('Signature-Input').first.delete_prefix('sig1=')}"
    signature = request.headers.get("Signature").first[/sig1=:(.*):/, 1].unpack1("m0")
    expect(key.verify(nil, signature, base)).to be(true)
  end

  it "signs a request without a token or a body with the method and target uri only" do
    request = request_with
    described_class.new(key_id: "k", private_key: key).authenticate_request(request).resume

    expect(request.headers.get("Authorization")).to be_nil
    expect(request.headers.get("Signature-Input").first).to start_with('sig1=("@method" "@target-uri");')
  end
end
