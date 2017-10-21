using Microsoft.Extensions.CommandLineUtils;
using System;
using System.Threading.Tasks;

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

                    var valid = (azureKeyVaultAccessToken.HasValue() || (azureKeyVaultClientId.HasValue() && azureKeyVaultClientSecret.HasValue()));
                    if (!valid)
                    {
                        application.Error.WriteLine("Either access token or clientId and client secret must be specified");
                        return Task.FromResult(-1);
                    }

                    var cmd = new SignCommand(application);
                    return cmd.SignAsync(file.Value,
                                         azureKeyVaultCertificateName.Value(),
                                         azureKeyVaultUrl.Value(),
                                         azureKeyVaultClientId.Value(),
                                         azureKeyVaultClientSecret.Value(),
                                         azureKeyVaultAccessToken.Value());
                });
            }
            );

            application.HelpOption("-? | -h | --help");
            application.VersionOption("-v | --version", typeof(Program).Assembly.GetName().Version.ToString(3));
            if (args.Length == 0 || args[0] != "sign")
            {
                application.ShowHelp();
            }
            return application.Execute(args);
        }
    }
}
