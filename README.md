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
       client_secret=<GOOGLE_CLIENT_SECRET> \
       fetch_groups=true
   ```

1. Create a role for a given Google group, or set of users mapping to a set of policies:

   Create a policy called hello: [vault polices](https://www.vaultproject.io/intro/getting-started/policies.html)

   **Emails/Users**
   ```sh
   $ vault write auth/google/role/hello \
       bound_domain=<DOMAIN> \
       bound_emails=myuseremail@<DOMAIN>,otheremail@<DOMAIN> \
       policies=hello
   ```

   **Groups**
   Note: The plugin requires administrative permissions to read the groups. It does work if the user is an admin, but otherwise fails.
   Use with caution.
   ```sh
   $ vault write auth/google/role/hello \
       bound_domain=<DOMAIN> \
       bound_groups=SecurityTeam,WebTeam \
       policies=hello
   ```

1. Login using Google credentials (NB we use `open` to navigate to the Google Auth URL to get the code).

   ```sh
   $ open $(vault read -field=url auth/google/code_url)
   $ vault write auth/google/login code=$GOOGLE_CODE role=hello
   ```

## Notes

* If running this inside a docker container or similar, you need to ensure the plugin has the IPC_CAP as well as vault.

  e.g.
  ```sh
  $ sudo setcap cap_ipc_lock=+ep /etc/vault/plugins/google-auth-vault-plugin
  ```

* When building remember your target platform.

  e.g. on MacOS targeting Linux:
  ```sh
  GOOS=linux make
  ```
* You may need to set [api_addr](https://www.vaultproject.io/docs/configuration/index.html#api_addr)

  This can be set at the top level for a standalone setup, or in a ha_storage stanza.

## License

This code is licensed under the MPLv2 license.
