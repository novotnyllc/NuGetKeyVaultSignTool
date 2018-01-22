using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Reflection;
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

        public async Task<int> SignAsync(string packagePath,
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
            var cert = new X509Certificate2(kvcert.Cer);



            var rsa = client.ToRSA(kvcert.KeyIdentifier, cert);
            
            var request = new SignPackageRequest(cert, signatureHashAlgorithm, timestampHashAlgorithm);
            
            // if cert is self-signed, put an it as the sole cert in the Chain property
            if (cert.IsSelfSigned())
            {
                var setter = typeof(SignPackageRequest).GetProperty("Chain", BindingFlags.Instance | BindingFlags.NonPublic)
                                                       .GetSetMethod(true);

                setter.Invoke(request, new object[] {new List<X509Certificate2>{cert}});
            }


            var logger = new NullLogger();
            var signatureProvider = new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

            string originalPackageCopyPath = null;
            try
            {
                originalPackageCopyPath = CopyPackage(packagePath);

                // For overwrite we need to first remove the signature and then sign the unsigned package
                if (overwrite)
                {
                    originalPackageCopyPath = CopyPackage(packagePath);

                    await RemoveSignatureAsync(logger, signatureProvider, packagePath, originalPackageCopyPath, CancellationToken.None);
                    await AddSignatureAndUpdatePackageAsync(logger, signatureProvider, request, originalPackageCopyPath, outputPath, CancellationToken.None);

                    FileUtility.Delete(originalPackageCopyPath);
                }
                else
                {
                    await AddSignatureAndUpdatePackageAsync(logger, signatureProvider, request, packagePath, outputPath, CancellationToken.None);
                }

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
                    FileUtility.Delete(originalPackageCopyPath);
                }
                catch
                {
                }
            }

            return 0;
        }

        static async Task AddSignatureAndUpdatePackageAsync(
            ILogger logger,
            ISignatureProvider signatureProvider,
            SignPackageRequest request,
            string packagePath,
            string outputPath,
            CancellationToken token)
        {
            var originalPackageCopyPath = CopyPackage(packagePath);

            using (var packageReadStream = File.OpenRead(packagePath))
            using (var packageWriteStream = File.Open(originalPackageCopyPath, FileMode.Open))
            using (var package = new SignedPackageArchive(packageReadStream, packageWriteStream))
            {
                var signer = new Signer(package, signatureProvider);
                await signer.SignAsync(request, logger, token);
            }

            OverwritePackage(originalPackageCopyPath, outputPath);
            FileUtility.Delete(originalPackageCopyPath);
        }

        static async Task RemoveSignatureAsync(
            ILogger logger,
            ISignatureProvider signatureProvider,
            string packagePath,
            string originalPackageCopyPath,
            CancellationToken token)
        {
            using (var packageReadStream = File.OpenRead(packagePath))
            using (var packageWriteStream = File.Open(originalPackageCopyPath, FileMode.Open))
            using (var package = new SignedPackageArchive(packageReadStream, packageWriteStream))
            {
                var signer = new Signer(package, signatureProvider);
                await signer.RemoveSignaturesAsync(logger, token);
            }
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
