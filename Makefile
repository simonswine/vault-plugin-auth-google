
BINDIR ?= $(CURDIR)/bin
PATH   := $(BINDIR):$(PATH)

GOIMPORT := github.com/simonswine/vault-plugin-auth-google

DOCKER_IMAGE_NAME ?= grapeshot/google-auth-vault-plugin

docker: google-auth-vault-plugin
	docker build -t $(DOCKER_IMAGE_NAME):$(shell git rev-parse --short HEAD) .

clean:
	rm google-auth-vault-plugin

lint:
	gometalinter --enable-all --vendor --deadline=5m

$(BINDIR)/mockgen:
	mkdir -p $(BINDIR)
	go build -o $(BINDIR)/mockgen ./vendor/github.com/golang/mock/mockgen

generate-mocks: $(BINDIR)/mockgen
	mockgen -package google -source google/provider.go -destination google/mocks_test.go
