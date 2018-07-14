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

namespace NuGetKeyVaultSignTool
{
    class SignCommand
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
                                         string keyVaultAccessToken,
                                         X509Certificate2 publicCertificate = null,
                                         KeyIdentifier keyIdentifier = null)
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

            if (publicCertificate != null && keyIdentifier != null)
            {
                // We call this here to verify it's a valid cert
                // It also implicitly validates the access token or credentials
                var kvcert = await client.GetCertificateAsync(keyVaultUrl, keyVaultCertificateName)
                                         .ConfigureAwait(false);
                publicCertificate = new X509Certificate2(kvcert.Cer);
                keyIdentifier = kvcert.KeyIdentifier;
            }
            
            var rsa = client.ToRSA(keyIdentifier, publicCertificate);
            var signatureProvider = new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

            var request = new AuthorSignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm);

            string originalPackageCopyPath = null;
            try
            {
                originalPackageCopyPath = CopyPackage(packagePath);

                using (var options = SigningOptions.CreateFromFilePaths(originalPackageCopyPath, outputPath, overwrite, signatureProvider, NullLogger.Instance))
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
