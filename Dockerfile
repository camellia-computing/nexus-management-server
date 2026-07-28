# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS admin-ui-builder
WORKDIR /app
COPY .node-version ./
RUN test "$(node --version)" = "v$(cat .node-version)" && corepack enable
WORKDIR /app/admin-ui
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml admin-ui/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY admin-ui ./
RUN pnpm build

FROM rust:1.97.0-bookworm@sha256:4700e599cc24fb4145b7f4a4c611695883e7be6e261cde0f3d4436eeb0af17c1 AS builder
WORKDIR /app
COPY rust-toolchain.toml ./
RUN actual="$(rustc --version)" \
    && actual="${actual#rustc }" \
    && test "${actual%% *}" = "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" \
    && test -s /etc/ssl/certs/ca-certificates.crt
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp /app/target/release/camellia-nexus-management-server /tmp/camellia-nexus-management-server

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG VERSION
ARG REVISION
ARG SOURCE
LABEL org.opencontainers.image.title="Camellia Nexus Management Server" \
      org.opencontainers.image.description="Server-authoritative licensing service for Camellia Nexus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.vendor="Camellia Computing" \
      org.opencontainers.image.licenses="LicenseRef-Camellia-Proprietary-1.0"
RUN test -n "$VERSION" \
    && test -n "$REVISION" \
    && test -n "$SOURCE"
WORKDIR /app
ENV HOME=/tmp \
    CAMELLIA_NEXUS_LICENSE_BIND=0.0.0.0:8088 \
    CAMELLIA_NEXUS_LOG_FORMAT=json \
    CAMELLIA_NEXUS_LOG_LEVEL=info \
    CAMELLIA_NEXUS_HTTP_LOG_LEVEL=info \
    CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL=warn
COPY --from=builder /tmp/camellia-nexus-management-server /usr/local/bin/camellia-nexus-management-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/migrations /app/migrations
COPY --from=admin-ui-builder /app/admin-ui/build /app/admin-ui/build
USER 10001:10001
EXPOSE 8088 8090
ENTRYPOINT ["camellia-nexus-management-server"]
