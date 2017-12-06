using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using NuGet.Common;
using NuGet.Packaging.Signing;

namespace NuGetKeyVaultSignTool
{
    class SignCommand
    {
        readonly CommandLineApplication application;
        
        public SignCommand(CommandLineApplication application)
        {
            this.application = application;
        }

        public async Task<int> SignAsync(string file,
                                         string timestampUrl,
                                         HashAlgorithmName signatureHashAlgorithm,
                                         HashAlgorithmName timestampeHashAlgorithm,
                                         SignatureType signatureType,
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
            var cert = new X509Certificate2(kvcert.Cer);



            var rsa = client.ToRSA(kvcert.KeyIdentifier, cert);

            // TODO: Add Hash Alg choice
            var request = new SignPackageRequest()
            {
                Certificate = cert,
                SignatureHashAlgorithm = signatureHashAlgorithm,
                TimestampHashAlgorithm = timestampeHashAlgorithm,
                SignatureType = signatureType
            };

            string tempFilePath = null;
            try
            {
                tempFilePath = CopyPackage(file);
                var signatureProvider = new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

                // remove first to overwrite
                // This command overwrites by default, like signtool
                using (var packageWriteStream = File.Open(tempFilePath, FileMode.Open))
                using (var package = new SignedPackageArchive(packageWriteStream))
                {
                    var signer = new Signer(package, signatureProvider);
                    await signer.RemoveSignaturesAsync(new NullLogger(), CancellationToken.None);
                }

                // Now sign
                using (var packageWriteStream = File.Open(tempFilePath, FileMode.Open))
                using (var package = new SignedPackageArchive(packageWriteStream))
                {
                    var signer = new Signer(package, signatureProvider);
                    await signer.SignAsync(request, new NullLogger(), CancellationToken.None);
                }

                OverwritePackage(tempFilePath, file);

            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                Console.Error.WriteLine(e.StackTrace);
                return -1;
            }
            finally
            {
                try
                {
                    FileUtility.Delete(tempFilePath);
                }
                catch
                {
                }
            }

            return 0;
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
