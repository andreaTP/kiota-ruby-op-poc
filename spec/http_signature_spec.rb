# frozen_string_literal: true

require_relative "../lib/open_payments/http_signature"

# test vectors from RFC 9421 appendix B
RSpec.describe OpenPayments::HttpSignature do
  let(:ed25519) do
    OpenSSL::PKey.read("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n")
  end

  it "computes the content digest of the RFC 9421 test request" do
    expect(described_class.content_digest('{"hello": "world"}'))
      .to eq("sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
  end

  it "reproduces the RFC 9421 B.2.6 ed25519 signature" do
    components = %w[date @method @path @authority content-type content-length]
    values = { "date" => "Tue, 20 Apr 2021 02:07:55 GMT", "@method" => "POST", "@path" => "/foo", "@authority" => "example.com",
               "content-type" => "application/json", "content-length" => "18" }
    params = described_class.signature_params(components, key_id: "test-key-ed25519", created: 1_618_884_473)
    base = described_class.signature_base(components, values, params)

    expect(params).to eq('("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"')
    expect(described_class.sign_base(base, ed25519))
      .to eq("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
  end

  it "signs a body, its digest, length and type, and the authorization" do
    headers = described_class.headers_for(method: :POST, url: "https://auth.example", body: "{}", content_type: "application/json",
                                          authorization: "GNAP token", key_id: "k", private_key: ed25519, created: 1)
    expect(headers["Signature-Input"])
      .to eq('sig1=("@method" "@target-uri" "authorization" "content-digest" "content-length" "content-type");created=1;keyid="k"')
    expect(headers["Content-Length"]).to eq("2")
    expect(headers["Signature"]).to start_with("sig1=:").and end_with(":")
  end

  it "signs the target uri with the path the request line carries" do
    expect(described_class.target_uri("https://auth.example")).to eq("https://auth.example/")
  end
end
