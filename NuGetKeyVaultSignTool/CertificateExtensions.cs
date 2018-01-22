using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool
{
    static class CertificateExtensions
    {
        public static bool IsSelfSigned(this X509Certificate2 cert) => cert.SubjectName.Name == cert.Issuer;
    }
}
