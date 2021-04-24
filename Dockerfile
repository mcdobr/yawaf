FROM rust as builder
WORKDIR yawaf
COPY . .
RUN ./copy_config.sh build --release --bin yawaf

FROM debian:stable-slim 
WORKDIR /usr/local/bin
COPY --from=builder /yawaf/target/release/yawaf /usr/local/bin/
# Can't figure out how to do both copies in a single layer right now
COPY --from=builder /yawaf/config /usr/local/bin/config/
ENTRYPOINT ["/usr/local/bin/yawaf"]
