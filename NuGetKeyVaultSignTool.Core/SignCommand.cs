using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGet.Protocol;
using RSAKeyVaultProvider;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NuGetKeyVaultSignTool;

public class SignCommand(ILogger logger)
{
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
        CertificateClient client = new(keyVaultUrl, credential);
        // We call this here to verify it's a valid cert
        // It also implicitly validates the access token or credentials
        Azure.Response<KeyVaultCertificateWithPolicy> kvcert = await client.GetCertificateAsync(keyVaultCertificateName, cancellationToken)
                                 .ConfigureAwait(false);
        X509Certificate2 publicCertificate = new(kvcert.Value.Cer);

        System.Security.Cryptography.RSA rsa = RSAFactory.Create(credential, kvcert.Value.KeyId, publicCertificate);

        return await SignAsync(packagePath, outputPath, timestampUrl, v3ServiceIndexUrl, packageOwners, signatureType, signatureHashAlgorithm, timestampHashAlgorithm, overwrite, publicCertificate, rsa, cancellationToken);
    }

    public async Task<bool> SignAsync(string packagePath, string outputPath, string timestampUrl, Uri v3ServiceIndex, IReadOnlyList<string> packageOwners,
                                      SignatureType signatureType, HashAlgorithmName signatureHashAlgorithm, HashAlgorithmName timestampHashAlgorithm,
                                      bool overwrite, X509Certificate2 publicCertificate, System.Security.Cryptography.RSA rsa, CancellationToken cancellationToken = default)
    {
        bool inPlaceSigning = string.Equals(packagePath, outputPath);
        bool usingWildCards = packagePath.Contains('*') || packagePath.Contains('?');
        IEnumerable<string> packagesToSign = LocalFolderUtility.ResolvePackageFromPath(packagePath);

        KeyVaultSignatureProvider signatureProvider = new(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl)));

        SignPackageRequest request = null;

        if(signatureType == SignatureType.Author)
            request = new AuthorSignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm);
        else if(signatureType == SignatureType.Repository)
            request = new RepositorySignPackageRequest(publicCertificate, signatureHashAlgorithm, timestampHashAlgorithm, v3ServiceIndex, packageOwners);
        else throw new ArgumentOutOfRangeException(nameof(signatureType));

        string originalPackageCopyPath = null;
        foreach(string package in packagesToSign)
        {
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogInformation("{SignAsync} [{package}]: Begin Signing {fileName}", nameof(SignAsync), package, Path.GetFileName(package));
            try
            {
                originalPackageCopyPath = CopyPackage(package);
                string signedPackagePath = outputPath;
                if(inPlaceSigning)
                {
                    signedPackagePath = package;
                }
                else if(usingWildCards)
                {
                    string packageFile = Path.GetFileName(package);
                    string pathName = Path.GetDirectoryName(outputPath + Path.DirectorySeparatorChar);
                    if(!Directory.Exists(pathName))
                    {
                        Directory.CreateDirectory(pathName);
                    }
                    signedPackagePath = pathName + Path.DirectorySeparatorChar + packageFile;
                }
                using SigningOptions options = SigningOptions.CreateFromFilePaths(originalPackageCopyPath, signedPackagePath, overwrite, signatureProvider, new NuGetLogger(logger, package));
                await SigningUtility.SignAsync(options, request, cancellationToken);
            }
            catch(Exception e)
            {
                logger.LogError(e, "{errorMessage}", e.Message);
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

                logger.LogInformation("{method} [{package}]: End Signing {fileName}", nameof(SignAsync), package, Path.GetFileName(package));
            }
        }

        return true;
    }

    private static string CopyPackage(string sourceFilePath)
    {
        string destFilePath = Path.GetTempFileName();
        File.Copy(sourceFilePath, destFilePath, overwrite: true);

        return destFilePath;
    }

    private static void OverwritePackage(string sourceFilePath, string destFilePath)
    {
        File.Copy(sourceFilePath, destFilePath, overwrite: true);
    }
}