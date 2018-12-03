FROM golang:1.11.2 AS build

ENV DEP_URL https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64
ENV DEP_HASH 287b08291e14f1fae8ba44374b26a2b12eb941af3497ed0ca649253e21ba2f83

RUN curl -sL -o /usr/local/bin/dep ${DEP_URL} && \
    echo "${DEP_HASH}  /usr/local/bin/dep" | sha256sum -c && \
    chmod +x /usr/local/bin/dep


WORKDIR /go/src/github.com/jetstack/vault-plugin-auth-google

ADD Gopkg.toml Gopkg.lock ./

RUN dep ensure -vendor-only

ADD . ./

RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-w' -o vault-plugin-auth-google

# Build SHA256 of plugin and create mount script
RUN echo "#!/bin/sh" > setup-vault-plugin-auth-google.sh && \
    echo "vault write sys/plugins/catalog/vault-plugin-auth-google \"sha_256=$(sha256sum vault-plugin-auth-google | cut -d' ' -f1)\" command=vault-plugin-auth-google" >> setup-vault-plugin-auth-google.sh && \
    chmod +x setup-vault-plugin-auth-google.sh

FROM alpine:3.8

COPY --from=build /go/src/github.com/jetstack/vault-plugin-auth-google/vault-plugin-auth-google /usr/local/bin
COPY --from=build /go/src/github.com/jetstack/vault-plugin-auth-google/setup-vault-plugin-auth-google.sh /usr/local/bin
