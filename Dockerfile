FROM golang:1.17.4-alpine AS builder

RUN apk add --update --no-cache make
WORKDIR /build

COPY . /build/

RUN make

FROM alpine:3.15.0

COPY --from=builder /build/target/db-auth-gateway /usr/local/bin/db-auth-gateway
COPY --from=builder /build/LICENSE /LICENSE

RUN addgroup -g 65532 -S gateway \
  && adduser -u 65532 -S gateway -G gateway

USER 65532

ENTRYPOINT [ "/usr/local/bin/db-auth-gateway" ]