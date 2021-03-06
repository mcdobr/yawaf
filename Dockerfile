FROM rust as builder
WORKDIR yawaf
COPY . .
RUN apt update && apt install -y libclang-dev clang
RUN ./copy_config.sh build --release --bin yawaf

FROM debian:stable-slim 
WORKDIR /usr/local/bin
COPY --from=builder /yawaf/target/release/yawaf /usr/local/bin/
# Can't figure out how to do both copies in a single layer right now
COPY --from=builder /yawaf/config /usr/local/bin/config/
COPY /rules /usr/local/bin/rules/
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/yawaf"]
