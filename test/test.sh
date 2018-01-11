#!/bin/sh

set -eu

# Need to define these in env
CLIENT_ID=${CLIENT_ID:-undefined}
CLIENT_SECRET=${CLIENT_SECRET:-undefined}
DOMAIN=${DOMAIN:-undefined}
EMAIL=${EMAIL:-undefined}
export VAULT_ADDR=http://localhost:8200

echo "Starting Vault in the Background (logs at vault.log)"
vault server -dev -config=./vault.json -log-level=debug >vault.log 2>&1 &
VAULT_PID=$!
trap "sleep 1; kill ${VAULT_PID}" EXIT

echo "Build and install plugin"
go build  -o google-auth-vault-plugin ./..
SHA256=$(shasum -a 256 "google-auth-vault-plugin" | cut -d' ' -f1)
vault write sys/plugins/catalog/google-auth-vault-plugin "sha_256=${SHA256}" command=google-auth-vault-plugin

echo "Enable plugin and configure it"
vault auth-enable -path=google -plugin-name=google-auth-vault-plugin plugin
vault write auth/google/config "client_id=${CLIENT_ID}" "client_secret=${CLIENT_SECRET}"
vault policy-write sys/policy/hello ./hello.hcl
vault write auth/google/role/hello policies=hello "bound_domain=${DOMAIN}" "bound_emails=${EMAIL}"

echo "Log the user in"
open $(vault read -field=url auth/google/code_url)
echo "Enter the code given to you by Google, followed by [ENTER]:"
read code
vault write auth/google/login code=${code} role=hello
