FROM golang:1.12.17 AS build

WORKDIR /go/src/github.com/simonswine/vault-plugin-auth-google

ADD go.mod go.sum ./

RUN go mod download

ADD . ./

RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-w' -o vault-plugin-auth-google

# Build SHA256 of plugin and create mount script
RUN echo "#!/bin/sh" > setup-vault-plugin-auth-google.sh && \
    echo "vault write sys/plugins/catalog/vault-plugin-auth-google \"sha_256=$(sha256sum vault-plugin-auth-google | cut -d' ' -f1)\" command=vault-plugin-auth-google" >> setup-vault-plugin-auth-google.sh && \
    chmod +x setup-vault-plugin-auth-google.sh

FROM alpine:3.9

COPY --from=build /go/src/github.com/simonswine/vault-plugin-auth-google/vault-plugin-auth-google /usr/local/bin
COPY --from=build /go/src/github.com/simonswine/vault-plugin-auth-google/setup-vault-plugin-auth-google.sh /usr/local/bin
