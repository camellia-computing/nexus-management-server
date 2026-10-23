# syntax=docker/dockerfile:1.24.0@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS admin-ui-builder
WORKDIR /app
COPY .node-version ./
RUN test "$(node --version)" = "v$(cat .node-version)" && corepack enable
WORKDIR /app/admin-ui
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml admin-ui/pnpm-workspace.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY admin-ui ./
RUN pnpm build

FROM rust:1.99.1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS builder
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

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
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
