FROM rust as builder
WORKDIR yawaf
COPY . .
RUN ./make.sh build --release --bin yawaf

FROM alpine:3.13
WORKDIR yawaf
COPY --from=builder /yawaf/target/release/yawaf /usr/local/bin
ENTRYPOINT ["./usr/local/bin/yawaf"]