using Microsoft.Extensions.CommandLineUtils;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Azure.Core;
using Azure.Identity;

namespace NuGetKeyVaultSignTool
{
    class Program
    {
        internal static int Main(string[] args)
        {

            var serviceCollection = new ServiceCollection()
                .AddLogging(builder =>
                {
                    builder.AddConsole();
                });
            var serviceProvider = serviceCollection.BuildServiceProvider();
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

            var application = new CommandLineApplication(throwOnUnexpectedArg: false);
            var signCommand = application.Command("sign", throwOnUnexpectedArg: false, configuration: signConfiguration =>
            {
                signConfiguration.Description = "Signs NuGet packages with the specified Key Vault certificate.";
                signConfiguration.HelpOption("-? | -h | --help");

                var packagePath = signConfiguration.Argument("packagePath", "Package to sign.");
                var outputPath = signConfiguration.Option("-o | --output", "The output file. If omitted, overwrites input.", CommandOptionType.SingleValue);
                var force = signConfiguration.Option("-f | --force", "Overwrites a sigature if it exists.", CommandOptionType.NoValue);
                var fileDigestAlgorithm = signConfiguration.Option("-fd | --file-digest", "The digest algorithm to hash the file with. Default option is sha256", CommandOptionType.SingleValue);
                var rfc3161TimeStamp = signConfiguration.Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue);
                var rfc3161Digest = signConfiguration.Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server. Default option is sha256", CommandOptionType.SingleValue);
                var signatureType = signConfiguration.Option("-st | --signature-type", "The signature type (omit for author, default. Only author is supported currently).", CommandOptionType.SingleValue);
                var v3ServiceIndexUrl = signConfiguration.Option("-v3si | --v3-service-index-url", "Specifies V3 Service Index Url. Required if SignatureType is Repository", CommandOptionType.SingleValue);
                var packageOwners = signConfiguration.Option("-own | --package-owner", "Package Owners. Required if SignatureType is Repository", CommandOptionType.MultipleValue);
                var azureKeyVaultUrl = signConfiguration.Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientId = signConfiguration.Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientSecret = signConfiguration.Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultTenantId = signConfiguration.Option("-kvt | --azure-key-vault-tenant-id", "The Tenant Id to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultCertificateName = signConfiguration.Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultAccessToken = signConfiguration.Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultMsi = signConfiguration.Option("-kvm | --azure-key-vault-use-msi", "Use a Managed Identity to access Azure Key Vault.", CommandOptionType.NoValue);

                signConfiguration.OnExecute(async () =>
                {
                    if (string.IsNullOrWhiteSpace(packagePath.Value))
                    {
                        logger.LogError("Path to file(s) to sign are requried");
                        return -1;
                    }

                    if (!azureKeyVaultUrl.HasValue())
                    {
                        logger.LogError("Key Vault URL not specified");
                        return -1;
                    }

                    if (!azureKeyVaultCertificateName.HasValue())
                    {
                        logger.LogError("Certificate name not specified");
                        return -1;
                    }

                    if (!rfc3161TimeStamp.HasValue())
                    {
                        logger.LogError("Timestamp url not specified");
                        return -1;
                    }

                    var valid = (azureKeyVaultAccessToken.HasValue() || azureKeyVaultMsi.HasValue() || (azureKeyVaultClientId.HasValue() && azureKeyVaultClientSecret.HasValue() && azureKeyVaultTenantId.HasValue()));
                    if (!valid)
                    {
                        logger.LogError("Either access token or clientId, client secret, and tenant id must be specified");
                        return -1;
                    }

                    var sigHashAlg = GetValueFromOption(fileDigestAlgorithm, AlgorithmFromInput, HashAlgorithmName.SHA256);
                    var timeHashAlg = GetValueFromOption(rfc3161Digest, AlgorithmFromInput, HashAlgorithmName.SHA256);
                    var sigType = GetValueFromOption(signatureType, SignatureTypeFromInput, SignatureType.Author);

                    Uri v3ServiceIndex = null;

                    if (sigType != SignatureType.Author)
                    {
                       // Check for service index and owners
                        if (!v3ServiceIndexUrl.HasValue())
                        {
                            logger.LogError("Service index url must be specified for repository signatures");
                            return -1;
                        }

                        if (!Uri.TryCreate(v3ServiceIndexUrl.Value(), UriKind.Absolute, out v3ServiceIndex))
                        {
                            logger.LogError($"Could not parse '{v3ServiceIndexUrl.Value()}' as a Uri");
                            return -1;
                        }

                        if (!packageOwners.HasValue())
                        {
                            logger.LogError("At least one package owner must be specified for repository signatures");
                            return -1;
                        }
                    }

                    if (!Uri.TryCreate(azureKeyVaultUrl.Value(), UriKind.Absolute, out Uri keyVaultUri))
                    {
                        logger.LogError($"Could not parse '{azureKeyVaultUrl.Value()}' as a Uri");
                        return -1;
                    }

                    var output = string.IsNullOrWhiteSpace(outputPath.Value()) ? packagePath.Value : outputPath.Value();


                    TokenCredential credential = null;

                    if (azureKeyVaultMsi.HasValue())
                    {
                        credential = new DefaultAzureCredential();
                    }
                    else if (!string.IsNullOrWhiteSpace(azureKeyVaultAccessToken.Value()))
                    {
                        credential = new AccessTokenCredential(azureKeyVaultAccessToken.Value(), DateTimeOffset.UtcNow.AddHours(1));
                    }
                    else
                    {
                        credential = new ClientSecretCredential(azureKeyVaultTenantId.Value(), azureKeyVaultClientId.Value(), azureKeyVaultClientSecret.Value());
                    }

                    var cmd = new SignCommand(logger);
                    var  result = await cmd.SignAsync(packagePath.Value,
                                         output,
                                         rfc3161TimeStamp.Value(),
                                         sigHashAlg,
                                         timeHashAlg,
                                         sigType,
                                         force.HasValue(),
                                         v3ServiceIndex,             
                                         packageOwners.Values,
                                         azureKeyVaultCertificateName.Value(),
                                         keyVaultUri,
                                         credential
                                         );

                    return result ? 0 : -1;
                });
            }
            );

            // Verify
            var verifyCommand = application.Command("verify", throwOnUnexpectedArg: false, configuration: verifyConfiguration =>
            {
                verifyConfiguration.Description = "Verifies NuGet packages are signed correctly";
                verifyConfiguration.HelpOption("-? | -h | --help");

                var file = verifyConfiguration.Argument("file", "File to sign.");

                verifyConfiguration.OnExecute(async () =>
                {
                    if (string.IsNullOrWhiteSpace(file.Value))
                    {
                        application.Error.WriteLine("All arguments are required");
                        return -1;
                    }

                    var cmd = new VerifyCommand(logger);
                    var buffer = new StringBuilder();
                    var result = await cmd.VerifyAsync(file.Value, buffer);
                    Console.WriteLine(buffer.ToString());
                    if (result)
                    {
                        Console.WriteLine("Signature is valid");
                    }
                    else
                    {
                        Console.Write("Signature is invalid");
                    }
                    return result ? 0 : -1;
                });
            }
            );


            application.HelpOption("-? | -h | --help");
            application.VersionOption("-v | --version", typeof(Program).Assembly.GetName().Version.ToString(3));
            if (args.Length == 0)
            {
                application.ShowHelp();
            }
            return application.Execute(args);
        }

        static HashAlgorithmName? AlgorithmFromInput(string value)
        {
            switch (value?.ToLower())
            {
                case "sha384":
                    return HashAlgorithmName.SHA384;
                case "sha512":
                    return HashAlgorithmName.SHA512;
                case null:
                case "sha256":
                    return HashAlgorithmName.SHA256;
                default:
                    return null;

            }
        }

        static SignatureType? SignatureTypeFromInput(string value)
        {
            switch (value?.ToLower())
            {
                case "author":
                    return SignatureType.Author;
                case "repository":
                    return SignatureType.Repository;

                default:
                    return null;
            }
        }

        static T GetValueFromOption<T>(CommandOption option, Func<string, T?> transform, T defaultIfNull) where T : struct
        {
            if (!option.HasValue())
            {
                return defaultIfNull;
            }
            return transform(option.Value()) ?? defaultIfNull;
        }

    }
}
