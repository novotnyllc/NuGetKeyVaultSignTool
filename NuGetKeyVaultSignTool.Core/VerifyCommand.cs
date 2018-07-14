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
using NuGet.Common;
using NuGet.Packaging;
using NuGet.Packaging.Signing;
using Microsoft.Extensions.Logging;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NuGetKeyVaultSignTool
{
    public class VerifyCommand
    {
        readonly ILogger logger;
        
        public VerifyCommand(ILogger logger)
        {
            this.logger = logger;
        }

        public async Task<bool> VerifyAsync(string file, StringBuilder buffer)
        {
            if (file == null)
            {
                throw new ArgumentNullException(nameof(file));
            }

            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            var trustProviders = SignatureVerificationProviderFactory.GetSignatureVerificationProviders();
            var verifier = new PackageSignatureVerifier(trustProviders);
            try
            {
                var result = 0;
                using (var package = new PackageArchiveReader(file))
                {
                    var verificationResult = await verifier.VerifySignaturesAsync(package, SignedPackageVerifierSettings.GetVerifyCommandDefaultPolicy(), CancellationToken.None);


                    if (verificationResult.Valid)
                    {
                        return verificationResult.Valid;
                    }
                    else
                    {
                        var logMessages = verificationResult.Results.SelectMany(p => p.Issues).Select(p => p .AsRestoreLogMessage()).ToList();
                        foreach (var msg in logMessages)
                        {
                            buffer.AppendLine(msg.Message);
                        }
                        if (logMessages.Any(m => m.Level >= NuGet.Common.LogLevel.Warning))
                        {
                            var errors = logMessages.Where(m => m.Level == NuGet.Common.LogLevel.Error).Count();
                            var warnings = logMessages.Where(m => m.Level == NuGet.Common.LogLevel.Warning).Count();

                            buffer.AppendLine($"Finished with {errors} errors and {warnings} warnings.");

                            result = errors;
                        }
                        return false;
                    }

                }
            }
            catch (Exception e)
            {
                logger.LogError(e, e.Message);
                return false;
            }
        }
    }
}
