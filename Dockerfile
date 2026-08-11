FROM golang:1.26.5-alpine3.24 AS builder

RUN apk update --no-cache \
  && apk upgrade --no-cache \
  && apk add --no-cache make
WORKDIR /build

COPY . /build/

RUN make

FROM alpine:3.24.1

COPY --from=builder /build/target/db-auth-gateway /usr/local/bin/db-auth-gateway
COPY --from=builder /build/LICENSE /LICENSE

RUN apk update --no-cache \
  && apk upgrade --no-cache \
  && addgroup -g 65532 -S gateway \
  && adduser -u 65532 -S gateway -G gateway

USER 65532

ENTRYPOINT [ "/usr/local/bin/db-auth-gateway" ]