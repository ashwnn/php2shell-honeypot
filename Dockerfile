FROM rust:1.90-slim-bookworm AS build
WORKDIR /build
COPY Cargo.* ./
COPY src ./src
# Prefer the reviewed host lockfile; the Docker test script exports it.
RUN test -f Cargo.lock || cargo generate-lockfile
RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /build/target/release/php2shell /usr/local/bin/php2shell
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["php2shell", "serve"]
CMD ["--host", "0.0.0.0", "--data", "/data"]
