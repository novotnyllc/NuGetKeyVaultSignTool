using Microsoft.Extensions.CommandLineUtils;
using System;
using System.IO;
using System.Threading.Tasks;
using NuGet.Common;

namespace NuGetKeyVaultSignTool
{
    class Program
    {
        internal static int Main(string[] args)
        {
            var application = new CommandLineApplication(throwOnUnexpectedArg: false);
            var signCommand = application.Command("sign", throwOnUnexpectedArg: false, configuration: signConfiguration =>
            {
                signConfiguration.Description = "Signs NuGet packages with the specified Key Vault certificate.";
                signConfiguration.HelpOption("-? | -h | --help");

                var file = signConfiguration.Argument("file", "File to sign.");

                var fileDigestAlgorithm = signConfiguration.Option("-fd | --file-digest", "The digest algorithm to hash the file with.", CommandOptionType.SingleValue);
                var rfc3161TimeStamp = signConfiguration.Option("-tr | --timestamp-rfc3161", "Specifies the RFC 3161 timestamp server's URL. If this option (or -t) is not specified, the signed file will not be timestamped.", CommandOptionType.SingleValue);
                var rfc3161Digest = signConfiguration.Option("-td | --timestamp-digest", "Used with the -tr switch to request a digest algorithm used by the RFC 3161 timestamp server.", CommandOptionType.SingleValue);
                var azureKeyVaultUrl = signConfiguration.Option("-kvu | --azure-key-vault-url", "The URL to an Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientId = signConfiguration.Option("-kvi | --azure-key-vault-client-id", "The Client ID to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultClientSecret = signConfiguration.Option("-kvs | --azure-key-vault-client-secret", "The Client Secret to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultCertificateName = signConfiguration.Option("-kvc | --azure-key-vault-certificate", "The name of the certificate in Azure Key Vault.", CommandOptionType.SingleValue);
                var azureKeyVaultAccessToken = signConfiguration.Option("-kva | --azure-key-vault-accesstoken", "The Access Token to authenticate to the Azure Key Vault.", CommandOptionType.SingleValue);

                signConfiguration.OnExecute(() =>
                {
                    if (string.IsNullOrWhiteSpace(file.Value))
                    {
                        application.Error.WriteLine("All arguments are required");
                        return Task.FromResult(-1);
                    }

                    if (!azureKeyVaultUrl.HasValue())
                    {
                        application.Error.WriteLine("Key Vault URL not specified");
                        return Task.FromResult(-1);
                    }

                    if (!azureKeyVaultCertificateName.HasValue())
                    {
                        application.Error.WriteLine("Certificate name not specified");
                        return Task.FromResult(-1);
                    }

                    if (!rfc3161TimeStamp.HasValue())
                    {
                        application.Error.WriteLine("Timestamp url not specified");
                        return Task.FromResult(-1);
                    }

                    var valid = (azureKeyVaultAccessToken.HasValue() || (azureKeyVaultClientId.HasValue() && azureKeyVaultClientSecret.HasValue()));
                    if (!valid)
                    {
                        application.Error.WriteLine("Either access token or clientId and client secret must be specified");
                        return Task.FromResult(-1);
                    }

                    var sigHashAlg = GetValueFromOption(fileDigestAlgorithm, AlgorithmFromInput, HashAlgorithmName.SHA256);
                    var timeHashAlg = GetValueFromOption(rfc3161Digest, AlgorithmFromInput, HashAlgorithmName.SHA256);

                    var cmd = new SignCommand(application);
                    return cmd.SignAsync(file.Value,
                                         rfc3161TimeStamp.Value(),
                                         sigHashAlg,
                                         timeHashAlg,
                                         azureKeyVaultCertificateName.Value(),
                                         azureKeyVaultUrl.Value(),
                                         azureKeyVaultClientId.Value(),
                                         azureKeyVaultClientSecret.Value(),
                                         azureKeyVaultAccessToken.Value());
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

                    if (!File.Exists(file.Value))
                    {
                        application.Error.WriteLine("File does not exist");
                        return -1;
                    }
                 
                    var cmd = new VerifyCommand(application);
                    var result = await cmd.VerifyAsync(file.Value);
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
