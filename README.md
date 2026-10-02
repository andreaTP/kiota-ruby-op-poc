# Open Payments with a Kiota Ruby client

A payment sent end to end through [Open Payments](https://openpayments.dev) with Ruby clients that
[Kiota](https://github.com/microsoft/kiota) generates from the official OpenAPI descriptions
(Open Payments 1.4.0: wallet address, auth and resource servers).

The flow is the one in interledger/open-payments-example: read both wallets, get an incoming payment
grant, create the incoming payment, get a quote grant, create the quote, request an interactive outgoing
payment grant (approved in the browser), continue the grant, create the outgoing payment, then poll the
incoming payment until it is paid in full.

Every call goes through the generated clients. Only two things are written by hand:

- [`gnap_authentication_provider.rb`](lib/open_payments/gnap_authentication_provider.rb): a Kiota
  authentication provider that adds `Authorization: GNAP <token>` and signs each request, using
  [`http_signature.rb`](lib/open_payments/http_signature.rb) (RFC 9421 signatures with Ed25519, RFC 9530 Content-Digest);
- [`demo.rb`](lib/open_payments/demo.rb): the flow itself.

## Run it

```
docker build -t op-demo .
docker run --rm op-demo
```

The first build takes a few minutes because it builds Kiota from source (see [Kiota build](#kiota-build)).

With no `OP_*` variables, the payment goes through a stand-in server started in the same process
([`stand_in.rb`](lib/open_payments/stand_in.rb)). It checks the GNAP token, Content-Digest and Ed25519
signature of every request, answers with the payloads the spec documents, and approves the
interactive grant on its own. The run ends with `payment complete`.

Without Docker, you need Ruby 3.3+, and Docker or a `kiota` binary to generate the clients:

```
bundle install
bin/pay
bundle exec rspec
```

The specs check the signatures against the RFC 9421 test vectors, and run the whole flow against the stand-in.

## The generated clients

The generated code is not committed. `bin/generate` writes it to `lib/open_payments/generated/`
(gitignored), where you can read it:

```
lib/open_payments/generated/
  wallet_address/wallet_address_client.rb   OpenPayments::WalletAddress::WalletAddressClient
  auth/auth_client.rb                       OpenPayments::Auth::AuthClient
  resource/resource_client.rb               OpenPayments::Resource::ResourceClient
```

With `KIOTA` set to a kiota binary, `bin/generate` runs it. Otherwise it builds the `generated` stage
of the Dockerfile and copies the result out. `bin/pay` and the specs run `bin/generate` when the
directory is missing, and `docker build` generates the clients inside the image.

The flow uses them like this:

```ruby
signer = OpenPayments::GnapAuthenticationProvider.new(key_id:, private_key:, access_token:)
adapter = MicrosoftKiotaFaraday::FaradayRequestAdapter.new(signer)
adapter.set_base_url(wallet.resource_server)

resource = OpenPayments::Resource::ResourceClient.new(adapter)
resource.incoming_payments.post(body).resume
resource.outgoing_payments.by_id(id).get.resume
```

## Pay on the Interledger test network

Set up the [test wallet](https://wallet.interledger-test.dev) (play money only, see
[openpayments.dev](https://openpayments.dev/sdk/before-you-begin/)):

1. Create an account and complete the KYC step. Only the email address has to be real.
2. Create an account with **New account**, open it and add play money with **Deposit**.
3. Add two wallet addresses with **Add wallet address**: one to send from, one to receive on.
   They can be in the same account or in two different ones.
4. In **Settings > Developer Keys**, open the sending wallet address and choose **Generate public & private key**.
   This downloads `private.key` and shows the key ID. `OP_KEY_ID` is that ID, a UUID, not the nickname you typed.

Then:

```
docker run --rm -it -p 3344:3344 -v $PWD/private.key:/key.pem \
  -e OP_KEY_ID=<key id> -e OP_PRIVATE_KEY_PATH=/key.pem \
  -e OP_SENDER_WALLET=https://ilp.interledger-test.dev/<sender> \
  -e OP_RECEIVER_WALLET=https://ilp.interledger-test.dev/<receiver> op-demo
```

Or, without Docker:

```
OP_KEY_ID=<key id> OP_PRIVATE_KEY_PATH=private.key \
OP_SENDER_WALLET=https://ilp.interledger-test.dev/<sender> \
OP_RECEIVER_WALLET=https://ilp.interledger-test.dev/<receiver> bin/pay
```

Open the printed link and approve the payment. The browser then goes back to `http://localhost:3344/callback`,
and the run continues. `OP_AMOUNT` sets the amount the receiver gets, in its asset scale
(default `100`, so 1.00 USD). `OP_CALLBACK_PORT` sets the callback port (default `3344`).

## Kiota build

The Ruby generator needs microsoft/kiota#8314 (enum wire values, and unions without a discriminator).
Until that is released, the Dockerfile builds Kiota from the pull request's head,
`andreaTP/kiota@c6baaa4`. Pass `--build-arg KIOTA_REPO=... --build-arg KIOTA_REF=...` to build another one.
The runtime gems are `microsoft_kiota_{abstractions,faraday,serialization_json}` 0.24.0.

The OpenAPI descriptions are pinned to interledger/open-payments-specifications
[`e1f499f9e`](https://github.com/interledger/open-payments-specifications/tree/e1f499f9e6b8241e8134593c31ff88643a048d51/openapi).
