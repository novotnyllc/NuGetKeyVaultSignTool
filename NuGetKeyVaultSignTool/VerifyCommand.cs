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
            try
            {
                using (var package = new PackageArchiveReader(file))
                {

                    var verifier = new PackageSignatureVerifier(new ISignatureVerificationProvider[] { new X509SignatureVerificationProvider() }, SignedPackageVerifierSettings.RequireSigned);

                    var result = await verifier.VerifySignaturesAsync(package, new NullLogger(), CancellationToken.None);
                    return result.Valid;
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
