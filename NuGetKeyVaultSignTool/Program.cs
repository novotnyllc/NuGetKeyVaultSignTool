using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging.Signing;
using System;
using System.Text;

namespace NuGetKeyVaultSignTool;

internal class Program
{
    internal static int Main(string[] args)
    {
        IServiceCollection serviceCollection = new ServiceCollection()
            .AddLogging(builder =>
            {
                builder.AddConsole();
            });
        ServiceProvider serviceProvider = serviceCollection.BuildServiceProvider();
        ILogger<Program> logger = serviceProvider.GetRequiredService<ILogger<Program>>();

        CommandLineApplication application = new(throwOnUnexpectedArg: false);
        CommandLineApplication signCommand = application.Command("sign", throwOnUnexpectedArg: false, configuration: signConfiguration =>
        {
            signConfiguration.Description = "Signs NuGet packages with the specified Key Vault certificate.";
            signConfiguration.HelpOption("-? | -h | --help");

            CommandArgument packagePath = signConfiguration.Argument("packagePath", "Package to sign.");
            CommandOption outputPath = signConfiguration.Option("-o | --output", "The output file. If omitted, overwrites input.", CommandOptionType.SingleValue);
            CommandOption force = signConfiguration.Option("-f | --force", "Overwrites a signature if it exists.", CommandOptionType.NoValue);
            CommandOption fileDigestAlgorithm = signConfiguration.Option("-fd | --file-digest", "The digest algorithm to hash the file with. Default option is sha256", CommandOptionType.SingleValue);
            CommandOption rfc3161TimeStamp = signConfiguration.Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue);
            CommandOption rfc3161Digest = signConfiguration.Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server. Default option is sha256", CommandOptionType.SingleValue);
            CommandOption signatureType = signConfiguration.Option("-st | --signature-type", "The signature type (omit for author, default. Only author is supported currently).", CommandOptionType.SingleValue);
            CommandOption v3ServiceIndexUrl = signConfiguration.Option("-v3si | --v3-service-index-url", "Specifies V3 Service Index Url. Required if SignatureType is Repository", CommandOptionType.SingleValue);
            CommandOption packageOwners = signConfiguration.Option("-own | --package-owner", "Package Owners. Required if SignatureType is Repository", CommandOptionType.MultipleValue);
            CommandOption azureKeyVaultUrl = signConfiguration.Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultClientId = signConfiguration.Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultClientSecret = signConfiguration.Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultTenantId = signConfiguration.Option("-kvt | --azure-key-vault-tenant-id", "The Tenant Id to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultCertificateName = signConfiguration.Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultAccessToken = signConfiguration.Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
            CommandOption azureKeyVaultMsi = signConfiguration.Option("-kvm | --azure-key-vault-managed-identity", "Use a Managed Identity to access Azure Key Vault.", CommandOptionType.NoValue);

            signConfiguration.OnExecute(async () =>
            {
                if(string.IsNullOrWhiteSpace(packagePath.Value))
                {
                    logger.LogError("Path to file(s) to sign are required");
                    return -1;
                }

                if(!azureKeyVaultUrl.HasValue())
                {
                    logger.LogError("Key Vault URL not specified");
                    return -1;
                }

                if(!azureKeyVaultCertificateName.HasValue())
                {
                    logger.LogError("Certificate name not specified");
                    return -1;
                }

                if(!rfc3161TimeStamp.HasValue())
                {
                    logger.LogError("Timestamp url not specified");
                    return -1;
                }

                bool valid = (azureKeyVaultAccessToken.HasValue() || azureKeyVaultMsi.HasValue() || (azureKeyVaultClientId.HasValue() && azureKeyVaultClientSecret.HasValue() && azureKeyVaultTenantId.HasValue()));
                if(!valid)
                {
                    logger.LogError("Either access token or clientId, client secret, and tenant id must be specified");
                    return -1;
                }

                HashAlgorithmName sigHashAlg = GetValueFromOption(fileDigestAlgorithm, AlgorithmFromInput, HashAlgorithmName.SHA256);
                HashAlgorithmName timeHashAlg = GetValueFromOption(rfc3161Digest, AlgorithmFromInput, HashAlgorithmName.SHA256);
                SignatureType sigType = GetValueFromOption(signatureType, SignatureTypeFromInput, SignatureType.Author);

                Uri v3ServiceIndex = null;

                if(sigType != SignatureType.Author)
                {
                    // Check for service index and owners
                    if(!v3ServiceIndexUrl.HasValue())
                    {
                        logger.LogError("Service index url must be specified for repository signatures");
                        return -1;
                    }

                    if(!Uri.TryCreate(v3ServiceIndexUrl.Value(), UriKind.Absolute, out v3ServiceIndex))
                    {
                        logger.LogError("Could not parse '{v3ServiceIndexUrl}' as a Uri", v3ServiceIndexUrl.Value());
                        return -1;
                    }

                    if(!packageOwners.HasValue())
                    {
                        logger.LogError("At least one package owner must be specified for repository signatures");
                        return -1;
                    }
                }

                if(!Uri.TryCreate(azureKeyVaultUrl.Value(), UriKind.Absolute, out Uri keyVaultUri))
                {
                    logger.LogError("Could not parse '{azureKeyVaultUrl}' as a Uri", azureKeyVaultUrl.Value());
                    return -1;
                }

                string output = string.IsNullOrWhiteSpace(outputPath.Value()) ? packagePath.Value : outputPath.Value();

                TokenCredential credential = null;

                if(azureKeyVaultMsi.HasValue())
                {
                    credential = new DefaultAzureCredential();
                }
                else if(!string.IsNullOrWhiteSpace(azureKeyVaultAccessToken.Value()))
                {
                    credential = new AccessTokenCredential(azureKeyVaultAccessToken.Value(), DateTimeOffset.UtcNow.AddHours(1));
                }
                else
                {
                    credential = new ClientSecretCredential(azureKeyVaultTenantId.Value(), azureKeyVaultClientId.Value(), azureKeyVaultClientSecret.Value());
                }

                SignCommand cmd = new(logger);
                bool result = await cmd.SignAsync(packagePath.Value,
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
        CommandLineApplication verifyCommand = application.Command("verify", throwOnUnexpectedArg: false, configuration: verifyConfiguration =>
        {
            verifyConfiguration.Description = "Verifies NuGet packages are signed correctly";
            verifyConfiguration.HelpOption("-? | -h | --help");

            CommandArgument file = verifyConfiguration.Argument("file", "File to sign.");

            verifyConfiguration.OnExecute(async () =>
            {
                if(string.IsNullOrWhiteSpace(file.Value))
                {
                    application.Error.WriteLine("All arguments are required");
                    return -1;
                }

                VerifyCommand cmd = new(logger);
                StringBuilder buffer = new();
                bool result = await cmd.VerifyAsync(file.Value, buffer);
                Console.WriteLine(buffer.ToString());
                if(result)
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
        if(args.Length == 0)
        {
            application.ShowHelp();
        }
        return application.Execute(args);
    }

    private static HashAlgorithmName? AlgorithmFromInput(string value)
    {
        return (value?.ToLower()) switch
        {
            "sha384" => (HashAlgorithmName?)HashAlgorithmName.SHA384,
            "sha512" => (HashAlgorithmName?)HashAlgorithmName.SHA512,
            null or "sha256" => (HashAlgorithmName?)HashAlgorithmName.SHA256,
            _ => null,
        };
    }

    private static SignatureType? SignatureTypeFromInput(string value)
    {
        return (value?.ToLower()) switch
        {
            "author" => (SignatureType?)SignatureType.Author,
            "repository" => (SignatureType?)SignatureType.Repository,
            _ => null,
        };
    }

    private static T GetValueFromOption<T>(CommandOption option, Func<string, T?> transform, T defaultIfNull) where T : struct
    {
        if(!option.HasValue())
        {
            return defaultIfNull;
        }
        return transform(option.Value()) ?? defaultIfNull;
    }
}