using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGetKeyVaultSignTool.BouncyCastle;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Store;

namespace NuGetKeyVaultSignTool
{
    class KeyVaultSignatureProvider : ISignatureProvider
    {
        private readonly RSA provider;
        private readonly ITimestampProvider timestampProvider;

        public KeyVaultSignatureProvider(RSA provider, ITimestampProvider timestampProvider)
        {
            this.provider = provider;
            this.timestampProvider = timestampProvider ?? throw new ArgumentNullException(nameof(timestampProvider));
        }

        public async Task<Signature> CreateSignatureAsync(SignPackageRequest request, SignatureContent signatureContent, ILogger logger, CancellationToken token)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (signatureContent == null)
            {
                throw new ArgumentNullException(nameof(signatureContent));
            }

            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            var authorSignature = CreateKeyVaultSignature(request.Certificate, signatureContent, request.SignatureType);
            var timestamped = await TimestampSignature(request, logger, authorSignature, token);

            return timestamped;
        }

        byte[] CreateKeyVaultSignature(X509Certificate2 publicCert, SignatureContent signatureContent, SignatureType signatureType)
        {
            var chain = new X509Chain();
            chain.Build(publicCert);

            // Get the chain as bc certs
            var additionals = chain.ChainElements.Cast<X509ChainElement>()
                                   .Select(ce => DotNetUtilities.FromX509Certificate(ce.Certificate))
                                   .ToList();

            chain.Dispose();

            var bcCer = DotNetUtilities.FromX509Certificate(publicCert);

            var store = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(additionals));

            var cti = new CommitmentTypeIndication(new DerObjectIdentifier(AttributeUtility.GetSignatureTypeOid(signatureType)));

            // CommitmentTypeIdentifier attribute
            var attr = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(Oids.CommitmentTypeIndication), new DerSet(cti));

            var asnvect = new Asn1EncodableVector
            {
                attr
            };
            var attribTable = new AttributeTable(asnvect);


            var generator = new CmsSignedDataGenerator();
            var builder = new SignerInfoGeneratorBuilder();
            builder.WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(attribTable));
            var b = builder.Build(new RsaSignatureFactory("SHA256WITHRSA", provider), bcCer);
            generator.AddSignerInfoGenerator(b);
            generator.AddCertificates(store);
            

            var msg = new CmsProcessableByteArray(signatureContent.GetBytes());
            var data = generator.Generate(msg, true);

            var encoded = data.GetEncoded();

            return encoded;
        }


        Task<Signature> TimestampSignature(SignPackageRequest request, ILogger logger, byte[] signature, CancellationToken token)
        {
            var timestampRequest = new TimestampRequest
            {
                SignatureValue = signature,
                Certificate = request.Certificate,
                SigningSpec = SigningSpecifications.V1,
                TimestampHashAlgorithm = request.TimestampHashAlgorithm
            };

            return timestampProvider.TimestampSignatureAsync(timestampRequest, logger, token);
        }
    }
}
