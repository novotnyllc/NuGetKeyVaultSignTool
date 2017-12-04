using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using NuGet.Common;
using NuGet.Packaging;
using NuGet.Packaging.Signing;

namespace NuGetKeyVaultSignTool
{
    class VerifyCommand
    {
        readonly CommandLineApplication application;
        
        public VerifyCommand(CommandLineApplication application)
        {
            this.application = application;
        }

        public async Task<bool> VerifyAsync(string file)
        {

            var trustProviders = SignatureVerificationProviderFactory.GetSignatureVerificationProviders();
            var verifier = new PackageSignatureVerifier(trustProviders, SignedPackageVerifierSettings.RequireSigned);
            try
            {
                var result = 0;
                using (var package = new PackageArchiveReader(file))
                {
                    var verificationResult = await verifier.VerifySignaturesAsync(package, CancellationToken.None);


                    if (verificationResult.Valid)
                    {
                        return verificationResult.Valid;
                    }
                    else
                    {
                        var logMessages = verificationResult.Results.SelectMany(p => p.Issues).Select(p => p.ToLogMessage()).ToList();
                        foreach (var msg in logMessages)
                        {
                            Console.WriteLine(msg.Message);
                        }
                        if (logMessages.Any(m => m.Level >= LogLevel.Warning))
                        {
                            var errors = logMessages.Where(m => m.Level == LogLevel.Error).Count();
                            var warnings = logMessages.Where(m => m.Level == LogLevel.Warning).Count();

                            Console.WriteLine($"Finished with {errors} errors and {warnings} warnings.");

                            result = errors;
                        }
                        return false;
                    }

                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                Console.Error.WriteLine(e.StackTrace);
                return false;
            }
        }
    }
}
