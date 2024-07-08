using Microsoft.Extensions.Logging;
using NuGet.Packaging;
using NuGet.Packaging.Signing;
using NuGet.Protocol;
using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NuGetKeyVaultSignTool;

public class VerifyCommand(ILogger logger)
{
    public async Task<bool> VerifyAsync(string file, StringBuilder buffer)
    {
        ArgumentNullException.ThrowIfNull(file);

        ArgumentNullException.ThrowIfNull(buffer);

        ISignatureVerificationProvider[] trustProviders =
        [
            new IntegrityVerificationProvider(),
            new SignatureTrustAndValidityVerificationProvider()
        ];
        PackageSignatureVerifier verifier = new(trustProviders);

        bool allPackagesVerified = true;

        try
        {
            int result = 0;
            System.Collections.Generic.IEnumerable<string> packagesToVerify = LocalFolderUtility.ResolvePackageFromPath(file);

            foreach(string packageFile in packagesToVerify)
            {
                using PackageArchiveReader package = new(packageFile);
                VerifySignaturesResult verificationResult = await verifier.VerifySignaturesAsync(package, SignedPackageVerifierSettings.GetVerifyCommandDefaultPolicy(), CancellationToken.None);

                if(verificationResult.IsValid)
                {
                    allPackagesVerified = true;
                }
                else
                {
                    System.Collections.Generic.List<NuGet.Common.RestoreLogMessage> logMessages = verificationResult.Results.SelectMany(p => p.Issues).Select(p => p.AsRestoreLogMessage()).ToList();
                    foreach(NuGet.Common.RestoreLogMessage msg in logMessages)
                    {
                        buffer.AppendLine(msg.Message);
                    }
                    if(logMessages.Any(m => m.Level >= NuGet.Common.LogLevel.Warning))
                    {
                        int errors = logMessages.Where(m => m.Level == NuGet.Common.LogLevel.Error).Count();
                        int warnings = logMessages.Where(m => m.Level == NuGet.Common.LogLevel.Warning).Count();

                        buffer.AppendLine($"Finished with {errors} errors and {warnings} warnings.");

                        result = errors;
                    }
                    allPackagesVerified = false;
                }
            }
        }
        catch(Exception e)
        {
            logger.LogError(e, "{errorMessage}", e.Message);
            return false;
        }

        return allPackagesVerified;
    }
}