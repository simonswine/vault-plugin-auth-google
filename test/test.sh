#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

VAULT="${SCRIPT_ROOT}/vault"

CLI_CLIENT_ID=${CLI_CLIENT_ID:-}
CLI_CLIENT_SECRET=${CLI_CLIENT_SECRET:-}
CLI_TTL=${CLI_TTL:-10h}
CLI_MAX_TTL=${CLI_MAX_TTL:-336h}
WEB_CLIENT_ID=${WEB_CLIENT_ID:-}
WEB_CLIENT_SECRET=${WEB_CLIENT_SECRET:-}
WEB_REDIRECT_URL=${WEB_REDIRECT_URL:-}
WEB_TTL=${WEB_TTL:-30m}
WEB_MAX_TTL=${WEB_MAX_TTL:-10h}
ALLOWED_DOMAINS=${ALLOWED_DOMAINS:-}
ALLOWED_GROUPS=${ALLOWED_GROUPS:-jetstack.io}
ALLOWED_USERS=${ALLOWED_USERS:-simon@swine.de}
DIRECTORY_SERVICE_ACCOUNT_KEY=${DIRECTORY_SERVICE_ACCOUNT_KEY:-}
DIRECTORY_IMPERSONATE_USER=${DIRECTORY_IMPERSONATE_USER:-matt.barker@jetstack.io}

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root-token

echo "build vault with patches and plugins"
VAULT_IMAGE_ID=$(docker build -q -f ${SCRIPT_ROOT}/../Dockerfile.vault ${SCRIPT_ROOT}/..)
VAULT_CONTAINER_ID=$(docker create "${VAULT_IMAGE_ID}")
docker cp "${VAULT_CONTAINER_ID}:/bin/vault" ${SCRIPT_ROOT}/vault
docker rm "${VAULT_CONTAINER_ID}"


# this block configures vault once it's up and running
{
    # wait for vault to be available
    while true; do
        if $VAULT status 2> /dev/null > /dev/null; then
            break
        fi
    done

    # enable google plugin
    $VAULT auth enable -path=google google

    # configure google plugin
    $VAULT write auth/google/config \
        "cli_client_id=${CLI_CLIENT_ID}" \
        "cli_client_secret=${CLI_CLIENT_SECRET}" \
        "cli_ttl=${CLI_TTL}" \
        "cli_max_ttl=${CLI_MAX_TTL}" \
        "web_client_id=${WEB_CLIENT_ID}" \
        "web_client_secret=${WEB_CLIENT_SECRET}" \
        "web_redirect_url=${WEB_REDIRECT_URL}" \
        "web_ttl=${WEB_TTL}" \
        "web_max_ttl=${WEB_MAX_TTL}" \
        "allowed_domains=${ALLOWED_DOMAINS:-}" \
        "allowed_groups=${ALLOWED_GROUPS:-}" \
        "allowed_users=${ALLOWED_USERS:-simon@swine.de}" \
        "directory_service_account_key=${DIRECTORY_SERVICE_ACCOUNT_KEY}" \
        "directory_impersonate_user=${DIRECTORY_IMPERSONATE_USER}"

    GOOGLE_ACCESSOR=$($VAULT read -format json /sys/auth | jq -r '.data | .["google/"].accessor')

    # setup permissions for groups
    GROUP_ALL_ID=$($VAULT write -field id identity/group name="jetstack-all" policies="jetstack-all", type="external")
    GROUP_LONDON_ID=$($VAULT write -field id identity/group name="jetstack-london" policies="jetstack-london" type="external")
    GROUP_SWINE_ID=$($VAULT write -field id identity/group name="swine" policies="swine" type="external")

    $VAULT write -field id identity/group-alias name="jetstack-all@jetstack.io" mount_accessor=${GOOGLE_ACCESSOR} canonical_id=${GROUP_ALL_ID}
    $VAULT write -field id identity/group-alias name="jetstack-london@jetstack.io" mount_accessor=${GOOGLE_ACCESSOR} canonical_id=${GROUP_LONDON_ID}
    $VAULT write -field id identity/group-alias name="\@swine.de" mount_accessor=${GOOGLE_ACCESSOR} canonical_id=${GROUP_SWINE_ID}
}&

echo "starting vault"
$VAULT server "-dev-root-token-id=${VAULT_TOKEN}" -dev "-config=${SCRIPT_ROOT}/vault.json" -log-level=debug

wait
