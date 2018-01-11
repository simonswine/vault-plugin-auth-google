path "secret/foo" {
  capabilities = ["create"]
  allowed_parameters = {
    "*" = ["foo-*"]
  }
}
