NuGetKeyVaultSignTool
=====================

This tool adds [code signatures to a NuGet package](https://docs.microsoft.com/en-us/nuget/reference/signed-packages-reference) using an X509 certificate stored in [Microsoft Azure Key Vault.](https://azure.microsoft.com/en-us/services/key-vault/)

# Getting started

This tool is a .NET Core global tool. It can be installed with `dotnet tool install --global NuGetKeyVaultSignTool`. The tool requires the .NET Core 3.1 SDK on Windows and .NET 5.0 on other platforms.

Example:

```ps1
# Install the tool
dotnet tool install --global NuGetKeyVaultSignTool

# Alternatively, install the tool locally
# dotnet tool install --tool-path . NuGetKeyVaultSignTool

# Produce a package
& dotnet pack src/MyLibrary/

# Execute code signing
& NuGetKeyVaultSignTool sign MyLibrary.1.0.0.nupkg `
  --file-digest sha256 `
  --timestamp-rfc3161 http://timestamp.digicert.com `
  --timestamp-digest sha256 `
  --azure-key-vault-url https://my-keyvault.vault.azure.net `
  --azure-key-vault-client-id 1234566789 `
  --azure-key-vault-tenant-id <the guid or domain> `
  --azure-key-vault-client-secret abcxyz `
  --azure-key-vault-certificate MyCodeSignCert
```

# Usage

The tool has two subcommands, `sign` and `verify`.

## `sign`

Signs a NuGet package using a certificate stored in Azure Key Vault.

Usage: `NuGetKeyVaultSignTool.exe sign [options] <FILE_PATH>`

FILE_PATH = the path to the .nupkg file produced by `dotnet pack` or `nuget.exe pack`.

Options:

* `-o | --output` - The output file. If omitted, overwrites input.
* `-f | --force` - Overwrites a signature if it exists.
* `-fd | --file-digest` - The digest algorithm to hash the file with. Default option is sha256
* `-tr | --timestamp-rfc3161` - Specifies the RFC 3161 timestamp server's URL.
* `-td | --timestamp-digest` - Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.
* `-st | --signature-type` - The signature type (omit for author, default. Only author is supported currently).
* `-kvu | --azure-key-vault-url` - The URL to an Azure Key Vault.
* `-kvt | --azure-key-vault-tenant-id` - The Tenant Id to authenticate to the Azure Key Vault..
* `-kvi | --azure-key-vault-client-id` - The Client ID to authenticate to the Azure Key Vault.
* `-kvs | --azure-key-vault-client-secret` - The Client Secret to authenticate to the Azure Key Vault.
* `-kvc | --azure-key-vault-certificate` - The name of the certificate in Azure Key Vault.
* `-kva | --azure-key-vault-accesstoken` - The Access Token to authenticate to the Azure Key Vault.
* `-kvm | --azure-key-vault-managed-identity` - Use a Managed Identity to access Azure Key Vault.

**Note** For the authentication options to Azure Key Vault, either one of the following options are required:

`azure-key-vault-client-id` and `azure-key-vault-client-secret` and `azure-key-vault-tenant-id` or `azure-key-vault-accesstoken` or `azure-key-vault-managed-identity`.

## `verify`

Verifies that a NuGet package has been code-signed.

Usage: `NuGetKeyVaultSignTool verify [options] <FILE_PATH>`

FILE_PATH = the path to the .nupkg file produced by `dotnet pack` or `nuget.exe pack`.
