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

                var result = await context.AcquireTokenAsync(resource, credential).ConfigureAwait(false);
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
            var kvcert = await client.GetCertificateAsync(keyVaultUrl, keyVaultCertificateName).ConfigureAwait(false);
            var cert = new X509Certificate2(kvcert.Cer);


            using (var package = new SignedPackageArchive(new ZipArchive(File.Open(file, FileMode.Open), ZipArchiveMode.Update, false)))
            {
                var rsa = client.ToRSA(kvcert.KeyIdentifier, cert);

                var signer = new Signer(package, new KeyVaultSignatureProvider(rsa, new Rfc3161TimestampProvider(new Uri(timestampUrl))));

                // TODO: Add Hash Alg choice
                var request = new SignPackageRequest()
                {
                    Certificate = cert,
                    SignatureHashAlgorithm = HashAlgorithmName.SHA256,
                    TimestampHashAlgorithm = HashAlgorithmName.SHA256
                };

                try
                {
                    await signer.SignAsync(request, new NullLogger(), CancellationToken.None);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e.Message);
                    Console.Error.WriteLine(e.StackTrace);
                    return -1;
                }

                return 0;
            }
        }
    }
}
