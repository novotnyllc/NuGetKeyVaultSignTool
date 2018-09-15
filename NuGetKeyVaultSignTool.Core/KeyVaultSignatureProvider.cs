using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGetKeyVaultSignTool.BouncyCastle;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;

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

        public async Task<PrimarySignature> CreatePrimarySignatureAsync(SignPackageRequest request, SignatureContent signatureContent, ILogger logger, CancellationToken token)
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

            logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Creating Primary signature");
            var authorSignature = CreateKeyVaultPrimarySignature(request, signatureContent, request.SignatureType);
            logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Primary signature completed");

            logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Timestamp primary signature");
            var timestamped = await TimestampPrimarySignatureAsync(request, logger, authorSignature, token);
            logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Timestamp completed");

            return timestamped;
        }

        public Task<PrimarySignature> CreateRepositoryCountersignatureAsync(RepositorySignPackageRequest request, PrimarySignature primarySignature, ILogger logger, CancellationToken token)
        {
            throw new NotImplementedException();
        }

        PrimarySignature CreateKeyVaultPrimarySignature(SignPackageRequest request, SignatureContent signatureContent, SignatureType signatureType)
        {
            // Get the chain

            var getter = typeof(SignPackageRequest).GetProperty("Chain", BindingFlags.Instance | BindingFlags.NonPublic)
                                                   .GetGetMethod(true);

            var certs = (IReadOnlyList<X509Certificate2>)getter.Invoke(request, null);
            
            
            var attribs = SigningUtility.CreateSignedAttributes(request, certs);

            // Convert .NET crypto attributes to Bouncy Castle
            var attribTable = new AttributeTable(new Asn1EncodableVector(attribs.Cast<CryptographicAttributeObject>()
                                                                                .Select(ToBcAttribute)
                                                                                .ToArray()));
            // SignerInfo generator setup
            var signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder()
                .WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(attribTable));


            // Subject Key Identifier (SKI) is smaller and less prone to accidental matching than issuer and serial
            // number.  However, to ensure cross-platform verification, SKI should only be used if the certificate
            // has the SKI extension attribute.

            // Try to look for the value 
            var bcCer = DotNetUtilities.FromX509Certificate(request.Certificate);
            var ext = bcCer.GetExtensionValue(new DerObjectIdentifier(Oids.SubjectKeyIdentifier));
            SignerInfoGenerator signerInfoGenerator;
            if (ext != null)
            {
                var ski = new SubjectKeyIdentifierStructure(ext);
                signerInfoGenerator = signerInfoGeneratorBuilder.Build(new RsaSignatureFactory(HashAlgorithmToBouncyCastle(request.SignatureHashAlgorithm), provider), ski.GetKeyIdentifier());
            }
            else
                signerInfoGenerator = signerInfoGeneratorBuilder.Build(new RsaSignatureFactory(HashAlgorithmToBouncyCastle(request.SignatureHashAlgorithm), provider), bcCer);

            
            var generator = new CmsSignedDataGenerator();
            
            generator.AddSignerInfoGenerator(signerInfoGenerator);

            // Get the chain as bc certs
            generator.AddCertificates(X509StoreFactory.Create("Certificate/Collection", 
                                                              new X509CollectionStoreParameters(certs.Select(DotNetUtilities.FromX509Certificate).
                                                                                                      ToList())));
            
            var msg = new CmsProcessableByteArray(signatureContent.GetBytes());
            var data = generator.Generate(msg, true);

            var encoded = data.GetEncoded();
            return PrimarySignature.Load(encoded);
        }

        Org.BouncyCastle.Asn1.Cms.Attribute ToBcAttribute(CryptographicAttributeObject obj)
        {
            var encodables = obj.Values.Cast<AsnEncodedData>().Select(d => Asn1Object.FromByteArray(d.RawData)).ToArray();
            var derSet = new DerSet(encodables);

            var attr = new Org.BouncyCastle.Asn1.Cms.Attribute(new DerObjectIdentifier(obj.Oid.Value), derSet);

            return attr;
        }

        static string HashAlgorithmToBouncyCastle(NuGet.Common.HashAlgorithmName algorithmName)
        {
            switch (algorithmName)
            {
                case NuGet.Common.HashAlgorithmName.SHA256:
                    return "SHA256WITHRSA";
                case NuGet.Common.HashAlgorithmName.SHA384:
                    return "SHA384WITHRSA";
                case NuGet.Common.HashAlgorithmName.SHA512:
                    return "SHA512WITHRSA";

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithmName));
            }
        }

        Task<PrimarySignature> TimestampPrimarySignatureAsync(SignPackageRequest request, ILogger logger, PrimarySignature signature, CancellationToken token)
        {
            var signatureValue = signature.GetSignatureValue();
            var messageHash = request.TimestampHashAlgorithm.ComputeHash(signatureValue);

            var timestampRequest = new TimestampRequest(
                signingSpecifications: SigningSpecifications.V1,
                hashedMessage: messageHash,
                hashAlgorithm: request.TimestampHashAlgorithm,
                target: SignaturePlacement.PrimarySignature
            );

            return timestampProvider.TimestampSignatureAsync(signature, timestampRequest, logger, token);
        }
    }
}
