# Kiota with microsoft/kiota#8314, until it is released
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS kiota
ARG KIOTA_REPO=https://github.com/andreaTP/kiota
ARG KIOTA_REF=c6baaa40067a509a6d251c4ab2695f9b84788e86
RUN mkdir /kiota-src \
 && curl -fsSL "$KIOTA_REPO/archive/$KIOTA_REF.tar.gz" | tar -xz --strip-components=1 -C /kiota-src \
 && dotnet publish /kiota-src/src/kiota/kiota.csproj -c Release -f net10.0 -p:TreatWarningsAsErrors=false -o /opt/kiota \
 && rm -rf /kiota-src

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
