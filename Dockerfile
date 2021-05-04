FROM golang:1.15.0-alpine AS builder

RUN apk add --update --no-cache curl make git

RUN go get mvdan.cc/gofumpt \
  && go get github.com/daixiang0/gci \
  && go get golang.org/x/lint/golint

RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.30.0

WORKDIR /build

COPY . /build/

RUN make

FROM alpine:3.12.0

COPY --from=builder /build/target/db-auth-gateway /usr/local/bin/db-auth-gateway
COPY --from=builder /build/LICENSE /LICENSE

RUN addgroup -g 65532 -S gateway \
  && adduser -u 65532 -S gateway -G gateway

USER 65532

ENTRYPOINT [ "/usr/local/bin/db-auth-gateway" ]
