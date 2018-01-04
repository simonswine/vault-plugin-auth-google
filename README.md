# HashiCorp Vault plugin for Google Auth.

A HashiCorp Vault plugin for Google Auth.

## Setup

The setup guide assumes some familiarity with Vault and Vault's plugin
ecosystem. You must have a Vault server already running, unsealed, and
authenticated.

1. Compile the plugin from source.

1. Move the compiled plugin into Vault's configured `plugin_directory`:

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

## License

This code is licensed under the MPLv2 license.
