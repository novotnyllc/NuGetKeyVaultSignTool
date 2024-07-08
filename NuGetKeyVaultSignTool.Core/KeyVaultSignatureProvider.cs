using NuGet.Common;
using NuGet.Packaging.Signing;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NuGetKeyVaultSignTool;

internal class KeyVaultSignatureProvider(RSA provider, ITimestampProvider timestampProvider) : ISignatureProvider
{
    // Occurs when SignedCms.ComputeSignature cannot read the certificate private key
    // "Invalid provider type specified." (INVALID_PROVIDER_TYPE)
    private const int INVALID_PROVIDER_TYPE_HRESULT = unchecked((int)0x80090014);

    private readonly ITimestampProvider timestampProvider = timestampProvider ?? throw new ArgumentNullException(nameof(timestampProvider));

    public async Task<PrimarySignature> CreatePrimarySignatureAsync(SignPackageRequest request, SignatureContent signatureContent, ILogger logger, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);

        ArgumentNullException.ThrowIfNull(signatureContent);

        ArgumentNullException.ThrowIfNull(logger);

        logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Creating Primary signature");
        PrimarySignature authorSignature = CreateKeyVaultPrimarySignature(request, signatureContent, logger);
        logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Primary signature completed");

        logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Timestamp primary signature");
        PrimarySignature timestamped = await TimestampPrimarySignatureAsync(request, logger, authorSignature, token);
        logger.LogInformation($"{nameof(CreatePrimarySignatureAsync)}: Timestamp completed");

        return timestamped;
    }

    public async Task<PrimarySignature> CreateRepositoryCountersignatureAsync(RepositorySignPackageRequest request, PrimarySignature primarySignature, ILogger logger, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);

        ArgumentNullException.ThrowIfNull(primarySignature);

        ArgumentNullException.ThrowIfNull(logger);

        token.ThrowIfCancellationRequested();

        MethodInfo getter = typeof(SignPackageRequest).GetProperty("Chain", BindingFlags.Instance | BindingFlags.NonPublic)
                                               .GetGetMethod(true);

        IReadOnlyList<X509Certificate2> certs = (IReadOnlyList<X509Certificate2>)getter.Invoke(request, null);

        CmsSigner cmsSigner = CreateCmsSigner(request, certs, logger);

        logger.LogInformation($"{nameof(CreateRepositoryCountersignatureAsync)}: Creating Counter signature");
        PrimarySignature signature = CreateKeyVaultRepositoryCountersignature(cmsSigner, request, primarySignature);
        logger.LogInformation($"{nameof(CreateRepositoryCountersignatureAsync)}: Counter signature completed");
        if(timestampProvider == null)
        {
            return signature;
        }
        else
        {
            logger.LogInformation($"{nameof(CreateRepositoryCountersignatureAsync)}: Timestamp Counter signature");
            PrimarySignature timestamped = await TimestampRepositoryCountersignatureAsync(request, logger, signature, token).ConfigureAwait(false);
            logger.LogInformation($"{nameof(CreateRepositoryCountersignatureAsync)}: Timestamp completed");
            return timestamped;
        }
    }

    private static PrimarySignature CreateKeyVaultRepositoryCountersignature(CmsSigner cmsSigner, SignPackageRequest request, PrimarySignature primarySignature)
    {
        SignedCms cms = new();
        cms.Decode(primarySignature.GetBytes());

        try
        {
            cms.SignerInfos[0].ComputeCounterSignature(cmsSigner);
        }
        catch(CryptographicException ex) when(ex.HResult == INVALID_PROVIDER_TYPE_HRESULT)
        {
            StringBuilder exceptionBuilder = new();
            exceptionBuilder.AppendLine("Invalid provider type");
            exceptionBuilder.AppendLine(CertificateUtility.X509Certificate2ToString(request.Certificate, NuGet.Common.HashAlgorithmName.SHA256));

            throw new SignatureException(NuGetLogCode.NU3001, exceptionBuilder.ToString());
        }

        return PrimarySignature.Load(cms);
    }

    private PrimarySignature CreateKeyVaultPrimarySignature(SignPackageRequest request, SignatureContent signatureContent, ILogger logger)
    {
        // Get the chain

        MethodInfo getter = typeof(SignPackageRequest).GetProperty("Chain", BindingFlags.Instance | BindingFlags.NonPublic)
                                               .GetGetMethod(true);

        IReadOnlyList<X509Certificate2> certs = (IReadOnlyList<X509Certificate2>)getter.Invoke(request, null);

        CmsSigner cmsSigner = CreateCmsSigner(request, certs, logger);

        ContentInfo contentInfo = new(signatureContent.GetBytes());
        SignedCms cms = new(contentInfo);

        try
        {
            cms.ComputeSignature(cmsSigner, false); // silent is false to ensure PIN prompts appear if CNG/CAPI requires it
        }
        catch(CryptographicException ex) when(ex.HResult == INVALID_PROVIDER_TYPE_HRESULT)
        {
            StringBuilder exceptionBuilder = new();
            exceptionBuilder.AppendLine("Invalid provider type");
            exceptionBuilder.AppendLine(CertificateUtility.X509Certificate2ToString(request.Certificate, NuGet.Common.HashAlgorithmName.SHA256));

            throw new SignatureException(NuGetLogCode.NU3001, exceptionBuilder.ToString());
        }

        return PrimarySignature.Load(cms);
    }

    private CmsSigner CreateCmsSigner(SignPackageRequest request, IReadOnlyList<X509Certificate2> chain, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(request);

        ArgumentNullException.ThrowIfNull(logger);

        // Subject Key Identifier (SKI) is smaller and less prone to accidental matching than issuer and serial
        // number.  However, to ensure cross-platform verification, SKI should only be used if the certificate
        // has the SKI extension attribute.
        CmsSigner signer;

        if(request.Certificate.Extensions[Oids.SubjectKeyIdentifier] == null)
        {
            signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, request.Certificate, provider);
        }
        else
        {
            signer = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier, request.Certificate, provider);
        }

        foreach(X509Certificate2 certificate in chain)
        {
            signer.Certificates.Add(certificate);
        }

        CryptographicAttributeObjectCollection attributes;

        if(request.SignatureType == SignatureType.Repository)
        {
            attributes = SigningUtility.CreateSignedAttributes((RepositorySignPackageRequest)request, chain);
        }
        else
        {
            attributes = SigningUtility.CreateSignedAttributes(request, chain);
        }

        foreach(CryptographicAttributeObject attribute in attributes)
        {
            signer.SignedAttributes.Add(attribute);
        }

        // We built the chain ourselves and added certificates.
        // Passing any other value here would trigger another chain build
        // and possibly add duplicate certs to the collection.
        signer.IncludeOption = X509IncludeOption.None;
        signer.DigestAlgorithm = request.SignatureHashAlgorithm.ConvertToOid();

        return signer;
    }

    private Task<PrimarySignature> TimestampPrimarySignatureAsync(SignPackageRequest request, ILogger logger, PrimarySignature signature, CancellationToken token)
    {
        byte[] signatureValue = signature.GetSignatureValue();
        byte[] messageHash = request.TimestampHashAlgorithm.ComputeHash(signatureValue);

        TimestampRequest timestampRequest = new(
            signingSpecifications: SigningSpecifications.V1,
            hashedMessage: messageHash,
            hashAlgorithm: request.TimestampHashAlgorithm,
            target: SignaturePlacement.PrimarySignature
        );

        return timestampProvider.TimestampSignatureAsync(signature, timestampRequest, logger, token);
    }

    private Task<PrimarySignature> TimestampRepositoryCountersignatureAsync(SignPackageRequest request, ILogger logger, PrimarySignature primarySignature, CancellationToken token)
    {
        RepositoryCountersignature repositoryCountersignature = RepositoryCountersignature.GetRepositoryCountersignature(primarySignature);
        byte[] signatureValue = repositoryCountersignature.GetSignatureValue();
        byte[] messageHash = request.TimestampHashAlgorithm.ComputeHash(signatureValue);

        TimestampRequest timestampRequest = new(
            signingSpecifications: SigningSpecifications.V1,
            hashedMessage: messageHash,
            hashAlgorithm: request.TimestampHashAlgorithm,
            target: SignaturePlacement.Countersignature
        );

        return timestampProvider.TimestampSignatureAsync(primarySignature, timestampRequest, logger, token);
    }
}