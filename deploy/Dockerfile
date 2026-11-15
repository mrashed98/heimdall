# Heimdall server image (also holds the CLI).
# Build from the repo root:  docker build -f deploy/Dockerfile -t heimdall .
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 ...

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- build: static musl binary (alpine's native target is musl) ---
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY --from=web /src/web/dist ./web/dist
COPY src ./src
# sqlx::migrate! reads these at compile time and embeds them in the binary,
# so they are needed here but not in the final image.
COPY migrations ./migrations
RUN cargo build --release --locked --bin heimdall

# --- runtime: no shell, no package manager; includes CA certificates ---
FROM gcr.io/distroless/static:nonroot
COPY --from=build /src/target/release/heimdall /usr/local/bin/heimdall
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/heimdall"]
CMD ["serve", "/etc/heimdall/heimdall.yaml"]
