DOCKER_IMAGE_NAME ?= grapeshot/google-auth-vault-plugin

google-auth-vault-plugin: $(shell find . -name *.go)
	go build -o google-auth-vault-plugin ./

docker: google-auth-vault-plugin
	docker build -t $(DOCKER_IMAGE_NAME):$(shell git rev-parse --short HEAD) .

clean:
	rm google-auth-vault-plugin

lint:
	gometalinter --enable-all --vendor --deadline=5m
