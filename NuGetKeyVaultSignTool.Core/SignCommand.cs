using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging.Signing;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using NuGet.Protocol;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using RSAKeyVaultProvider;

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
                                         Uri v3ServiceIndexUrl,
                                         IReadOnlyList<string> packageOwners,
                                         string keyVaultCertificateName,
                                         Uri keyVaultUrl,
                                         TokenCredential credential,
                                         CancellationToken cancellationToken = default)
        {
            

            var client = new CertificateClient(keyVaultUrl, credential);
            // We call this here to verify it's a valid cert
            // It also implicitly validates the access token or credentials
            var kvcert = await client.GetCertificateAsync(keyVaultCertificateName, cancellationToken)
                                     .ConfigureAwait(false);
            var publicCertificate = new X509Certificate2(kvcert.Value.Cer);


            var rsa = RSAFactory.Create(credential, kvcert.Value.KeyId, publicCertificate);

            return await SignAsync(packagePath, outputPath, timestampUrl, v3ServiceIndexUrl, packageOwners, signatureType, signatureHashAlgorithm, timestampHashAlgorithm, overwrite, publicCertificate, rsa, cancellationToken);
        }

        public async Task<bool> SignAsync(string packagePath, string outputPath, string timestampUrl, Uri v3ServiceIndex, IReadOnlyList<string> packageOwners,
                                          SignatureType signatureType, HashAlgorithmName signatureHashAlgorithm, HashAlgorithmName timestampHashAlgorithm, 
                                          bool overwrite, X509Certificate2 publicCertificate, System.Security.Cryptography.RSA rsa, CancellationToken cancellationToken = default)
        {
            bool inPlaceSigning = String.Equals(packagePath, outputPath);
            bool usingWildCards = packagePath.Contains('*') || packagePath.Contains('?');
            var packagesToSign = LocalFolderUtility.ResolvePackageFromPath(packagePath);
            
            var signatureProvider = new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

            SignPackageRequest request = null;

            if (signatureType == SignatureType.Author)
                request = new AuthorSignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm);
            else if (signatureType == SignatureType.Repository)
                request = new RepositorySignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm, v3ServiceIndex, packageOwners);
            else throw new ArgumentOutOfRangeException(nameof(signatureType));

            string originalPackageCopyPath = null;
            foreach (var package in packagesToSign)
            {
                cancellationToken.ThrowIfCancellationRequested();
                logger.LogInformation($"{nameof(SignAsync)} [{package}]: Begin Signing {Path.GetFileName(package)}");
                try
                {
                    originalPackageCopyPath = CopyPackage(package);
                    string signedPackagePath = outputPath;
                    if (inPlaceSigning)
                    {
                        signedPackagePath = package;
                    }
                    else if (usingWildCards)
                    {
                        var packageFile = Path.GetFileName(package);
                        string pathName = Path.GetDirectoryName(outputPath + Path.DirectorySeparatorChar);
                        if (!Directory.Exists(pathName))
                        {
                            Directory.CreateDirectory(pathName);
                        }
                        signedPackagePath = pathName + Path.DirectorySeparatorChar + packageFile;
                    }
                    using var options = SigningOptions.CreateFromFilePaths(originalPackageCopyPath, signedPackagePath, overwrite, signatureProvider, new NuGetLogger(logger, package));
                    await SigningUtility.SignAsync(options, request, cancellationToken);
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
