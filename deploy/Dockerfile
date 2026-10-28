# One image with both the proxy and the demo app. Builds natively on
# linux/amd64 and linux/arm64 (a Raspberry Pi 5 takes a while the first time).

FROM node:22-bookworm-slim AS client
WORKDIR /src/client
COPY client/package.json client/package-lock.json ./
RUN npm ci --ignore-scripts
COPY client/ ./
RUN npm run build

FROM rust:1.95-bookworm AS build
# pingora's zlib-ng needs cmake
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY rulepacks/ rulepacks/
COPY testvectors/ testvectors/
RUN cargo build --release --locked -p signprint-proxy -p signprint-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/signprint signprint \
 && mkdir -p /var/lib/signprint /usr/share/signprint/static && chown signprint /var/lib/signprint
COPY --from=build /src/target/release/signprint-proxy /src/target/release/signprint-demo /usr/local/bin/
COPY --from=client /src/client/dist/signprint.js /usr/share/signprint/static/
ENV STATIC_DIR=/usr/share/signprint/static
USER signprint
WORKDIR /var/lib/signprint
ENTRYPOINT ["signprint-proxy"]
CMD ["run", "/etc/signprint/signprint.toml"]
