FROM debian:bookworm-slim AS kiota
ARG KIOTA_VERSION=v1.38.0
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip libicu72 \
 && arch="$([ "$TARGETARCH" = arm64 ] && echo arm64 || echo x64)" \
 && curl -fsSL -o /tmp/kiota.zip "https://github.com/microsoft/kiota/releases/download/$KIOTA_VERSION/linux-$arch.zip" \
 && unzip -q /tmp/kiota.zip -d /opt/kiota && chmod +x /opt/kiota/kiota && rm /tmp/kiota.zip

FROM kiota AS generate
COPY bin/generate /usr/local/bin/generate
RUN KIOTA=/opt/kiota/kiota generate /generated

# bin/generate exports this stage when there is no local kiota
FROM scratch AS generated
COPY --from=generate /generated /

FROM ruby:3.3-slim AS gems
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
COPY Gemfile Gemfile.lock ./
RUN bundle install

FROM ruby:3.3-slim
WORKDIR /app
COPY --from=gems /usr/local/bundle /usr/local/bundle
COPY . .
COPY --from=generate /generated lib/open_payments/generated
ENV OP_CALLBACK_HOST=0.0.0.0
EXPOSE 3344
ENTRYPOINT ["bin/pay"]
