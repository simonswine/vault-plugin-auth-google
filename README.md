# HashiCorp Vault plugin for Google Auth.

A HashiCorp Vault plugin for Google Auth.

## Setup

The setup guide assumes some familiarity with Vault and Vault's plugin
ecosystem. You must have a Vault server already running, unsealed, and
authenticated.

1. Compile the plugin from source.

2. Move the compiled plugin into Vault's configured `plugin_directory`:

   ```sh
   $ mv google-auth-vault-plugin /etc/vault/plugins/google-auth-vault-plugin
   ```

1. Calculate the SHA256 of the plugin and register it in Vault's plugin catalog.
If you are downloading the pre-compiled binary, it is highly recommended that
you use the published checksums to verify integrity.

   ```sh
   $ export SHA256=$(shasum -a 256 "/etc/vault/plugins/google-auth-vault-plugin" | cut -d' ' -f1)
   $ vault write sys/plugins/catalog/google-auth-vault-plugin \
       sha_256="${SHA256}" \
       command="google-auth-vault-plugin"
   ```

1. Mount the auth method:

   ```sh
   $ vault auth-enable \
       -path="google" \
       -plugin-name="google-auth-vault-plugin" plugin
   ```

1. Create an OAuth client ID in [the Google Cloud Console](https://console.cloud.google.com/apis/credentials), of type "Other".

1. Configure the auth method:

   ```sh
   $ vault write auth/google/config \
       client_id=<GOOGLE_CLIENT_ID> \
       client_secret=<GOOGLE_CLIENT_SECRET>
   ```

1. Create a role for a given Google group, mapping to a set of policies:

   ```sh
   $ vault write auth/google/role/hello \
       bound_domain=<DOMAIN> \
       bound_emails=tom@<DOMAIN> \
       policies=hello
   ```

1. Login using Google credentials (NB we use `open` to navigate to the Google Auth URL to get the code).

   ```sh
   $ open $(vault read -field=url auth/google/code_url)
   $ vault write auth/google/login code=$GOOGLE_CODE role=hello
   ```

## License

This code is licensed under the MPLv2 license.
