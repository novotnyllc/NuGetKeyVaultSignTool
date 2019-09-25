using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging.Signing;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using NuGet.Protocol;

namespace NuGetKeyVaultSignTool
{
    public class SignCommand
    {
        readonly ILogger logger;
        
        public SignCommand(ILogger logger)
        {
            this.logger = logger;
        }

        public async Task<bool> SignAsync(string packagePath,
                                         string outputPath,
                                         string timestampUrl,
                                         HashAlgorithmName signatureHashAlgorithm,
                                         HashAlgorithmName timestampHashAlgorithm,
                                         SignatureType signatureType,
                                         bool overwrite,
                                         string keyVaultCertificateName,
                                         string keyVaultUrl,
                                         string keyVaultClientId,
                                         string keyVaultClientSecret,
                                         string keyVaultAccessToken)
        {
            string validatedToken = null;

            async Task<string> Authenticate(string authority, string resource, string scope)
            {
                if (!string.IsNullOrWhiteSpace(keyVaultAccessToken))
                {
                    validatedToken = keyVaultAccessToken;
                    return keyVaultAccessToken;
                }

                var context = new AuthenticationContext(authority);
                var credential = new ClientCredential(keyVaultClientId, keyVaultClientSecret);

                var result = await context.AcquireTokenAsync(resource, credential)
                                          .ConfigureAwait(false);
                if (result == null)
                {
                    throw new InvalidOperationException("Authentication to Azure failed.");
                }
                validatedToken = result.AccessToken;
                return result.AccessToken;
            }

            var client = new KeyVaultClient(Authenticate, new HttpClient());


            // We call this here to verify it's a valid cert
            // It also implicitly validates the access token or credentials
            var kvcert = await client.GetCertificateAsync(keyVaultUrl, keyVaultCertificateName)
                                     .ConfigureAwait(false);
            var publicCertificate = new X509Certificate2(kvcert.Cer);
            var keyIdentifier = kvcert.KeyIdentifier;


            var rsa = client.ToRSA(keyIdentifier, publicCertificate);

            return await SignAsync(packagePath, outputPath, timestampUrl, signatureHashAlgorithm, timestampHashAlgorithm, overwrite, publicCertificate, rsa);
        }

        public async Task<bool> SignAsync(string packagePath, string outputPath, string timestampUrl, HashAlgorithmName signatureHashAlgorithm, HashAlgorithmName timestampHashAlgorithm, bool overwrite, X509Certificate2 publicCertificate, System.Security.Cryptography.RSA rsa)
        {
            var packagesToSign = LocalFolderUtility.ResolvePackageFromPath(packagePath);
            
            var signatureProvider = new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

            var request = new AuthorSignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm);

            string originalPackageCopyPath = null;
            foreach (var package in packagesToSign)
            {
                logger.LogInformation($"{nameof(SignAsync)} [{package}]: Begin Signing {Path.GetFileName(package)}");
                try
                {
                    originalPackageCopyPath = CopyPackage(package);

                    using (var options = SigningOptions.CreateFromFilePaths(originalPackageCopyPath, outputPath, overwrite, signatureProvider, new NuGetLogger(logger, package)))
                    {
                        await SigningUtility.SignAsync(options, request, CancellationToken.None);
                    }
                }
                catch (Exception e)
                {
                    logger.LogError(e, e.Message);
                    return false;
                }
                finally
                {
                    try
                    {
                        FileUtility.Delete(originalPackageCopyPath);
                    }
                    catch
                    {
                    }

                    logger.LogInformation($"{nameof(SignAsync)} [{package}]: End Signing {Path.GetFileName(package)}");
                }
            }

            return true;
        }


        static string CopyPackage(string sourceFilePath)
        {
            var destFilePath = Path.GetTempFileName();
            File.Copy(sourceFilePath, destFilePath, overwrite: true);

            return destFilePath;
        }

        static void OverwritePackage(string sourceFilePath, string destFilePath)
        {
            File.Copy(sourceFilePath, destFilePath, overwrite: true);
        }
    }
}
