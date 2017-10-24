using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Collections;

namespace NuGetKeyVaultSignTool.BouncyCastle
{

    internal class X509Utilities
    {
        private static readonly Asn1Null derNull = DerNull.Instance;

        private static readonly IDictionary algorithms = new Hashtable();
        private static readonly IDictionary exParams = new Hashtable();
        private static readonly ISet noParams = new HashSet();

        static X509Utilities()
        {
            algorithms.Add("MD2WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD2WithRsaEncryption);
            algorithms.Add("MD2WITHRSA", PkcsObjectIdentifiers.MD2WithRsaEncryption);
            algorithms.Add("MD5WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD5WithRsaEncryption);
            algorithms.Add("MD5WITHRSA", PkcsObjectIdentifiers.MD5WithRsaEncryption);
            algorithms.Add("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            algorithms.Add("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            algorithms.Add("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            algorithms.Add("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            algorithms.Add("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            algorithms.Add("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            algorithms.Add("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            algorithms.Add("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            algorithms.Add("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            algorithms.Add("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            algorithms.Add("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
            algorithms.Add("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            algorithms.Add("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
            algorithms.Add("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            algorithms.Add("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
            algorithms.Add("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            algorithms.Add("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
            algorithms.Add("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
            algorithms.Add("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
            algorithms.Add("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
            algorithms.Add("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
            algorithms.Add("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
            algorithms.Add("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);
            algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
            algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
            algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
            algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);
            algorithms.Add("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            algorithms.Add("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            algorithms.Add("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            algorithms.Add("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            algorithms.Add("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
            noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            noParams.Add(NistObjectIdentifiers.DsaWithSha224);
            noParams.Add(NistObjectIdentifiers.DsaWithSha256);
            noParams.Add(NistObjectIdentifiers.DsaWithSha384);
            noParams.Add(NistObjectIdentifiers.DsaWithSha512);

            //
            // RFC 4491
            //
            noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
            noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            exParams.Add("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgId, 20));

            AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            exParams.Add("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgId, 28));

            AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            exParams.Add("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgId, 32));

            AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            exParams.Add("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgId, 48));

            AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            exParams.Add("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgId, 64));
        }

        /**
		 * Return the digest algorithm using one of the standard JCA string
		 * representations rather than the algorithm identifier (if possible).
		 */
        private static string GetDigestAlgName(
            DerObjectIdentifier digestAlgOID)
        {
            if (PkcsObjectIdentifiers.MD5.Equals(digestAlgOID))
            {
                return "MD5";
            }
            else if (OiwObjectIdentifiers.IdSha1.Equals(digestAlgOID))
            {
                return "SHA1";
            }
            else if (NistObjectIdentifiers.IdSha224.Equals(digestAlgOID))
            {
                return "SHA224";
            }
            else if (NistObjectIdentifiers.IdSha256.Equals(digestAlgOID))
            {
                return "SHA256";
            }
            else if (NistObjectIdentifiers.IdSha384.Equals(digestAlgOID))
            {
                return "SHA384";
            }
            else if (NistObjectIdentifiers.IdSha512.Equals(digestAlgOID))
            {
                return "SHA512";
            }
            else if (TeleTrusTObjectIdentifiers.RipeMD128.Equals(digestAlgOID))
            {
                return "RIPEMD128";
            }
            else if (TeleTrusTObjectIdentifiers.RipeMD160.Equals(digestAlgOID))
            {
                return "RIPEMD160";
            }
            else if (TeleTrusTObjectIdentifiers.RipeMD256.Equals(digestAlgOID))
            {
                return "RIPEMD256";
            }
            else if (CryptoProObjectIdentifiers.GostR3411.Equals(digestAlgOID))
            {
                return "GOST3411";
            }
            else
            {
                return digestAlgOID.Id;
            }
        }

        internal static string GetSignatureName(AlgorithmIdentifier sigAlgId)
        {
            Asn1Encodable parameters = sigAlgId.Parameters;

            if (parameters != null && !derNull.Equals(parameters))
            {
                if (sigAlgId.Algorithm.Equals(PkcsObjectIdentifiers.IdRsassaPss))
                {
                    RsassaPssParameters rsaParams = RsassaPssParameters.GetInstance(parameters);

                    return GetDigestAlgName(rsaParams.HashAlgorithm.Algorithm) + "withRSAandMGF1";
                }
                if (sigAlgId.Algorithm.Equals(X9ObjectIdentifiers.ECDsaWithSha2))
                {
                    Asn1Sequence ecDsaParams = Asn1Sequence.GetInstance(parameters);

                    return GetDigestAlgName((DerObjectIdentifier)ecDsaParams[0]) + "withECDSA";
                }
            }

            return sigAlgId.Algorithm.Id;
        }

        private static RsassaPssParameters CreatePssParams(
            AlgorithmIdentifier hashAlgId,
            int saltSize)
        {
            return new RsassaPssParameters(
                hashAlgId,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgId),
                new DerInteger(saltSize),
                new DerInteger(1));
        }

        internal static DerObjectIdentifier GetAlgorithmOid(
            string algorithmName)
        {
            algorithmName = algorithmName.ToUpperInvariant();

            if (algorithms.Contains(algorithmName))
            {
                return (DerObjectIdentifier)algorithms[algorithmName];
            }

            return new DerObjectIdentifier(algorithmName);
        }

        internal static AlgorithmIdentifier GetSigAlgID(
            DerObjectIdentifier sigOid,
            string algorithmName)
        {
            if (noParams.Contains(sigOid))
            {
                return new AlgorithmIdentifier(sigOid);
            }

            algorithmName = algorithmName.ToUpperInvariant();

            if (exParams.Contains(algorithmName))
            {
                return new AlgorithmIdentifier(sigOid, (Asn1Encodable)exParams[algorithmName]);
            }

            return new AlgorithmIdentifier(sigOid, DerNull.Instance);
        }

        internal static IEnumerable GetAlgNames()
        {
            return new EnumerableProxy(algorithms.Keys);
        }
    }


    /// <summary>
    /// Calculator factory class for signature generation in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
	public class RsaSignatureFactory: ISignatureFactory
	{
		private readonly AlgorithmIdentifier algID;
        private readonly string algorithm;
        private readonly RSA privateKey;
        private readonly HashAlgorithmName hashAlgorithmName;

       
        /// <summary>
        /// Constructor which also specifies a source of randomness to be used if one is required.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
		public RsaSignatureFactory(string algorithm, RSA privateKey)
		{
			DerObjectIdentifier sigOid = X509Utilities.GetAlgorithmOid (algorithm);

            this.algorithm = algorithm;
            this.privateKey = privateKey;
			this.algID = X509Utilities.GetSigAlgID (sigOid, algorithm);
            this.hashAlgorithmName = HashAlgNameFromBc(algorithm);
		}

		public object AlgorithmDetails
		{
			get { return this.algID; }
		}

        public IStreamCalculator CreateCalculator()
        {
            return new SigCalculator(privateKey, hashAlgorithmName);
        }

        // translate alg to HashAlgName
        static HashAlgorithmName HashAlgNameFromBc(string algorithm)
        {
            switch(algorithm.ToUpperInvariant())
            {
                case "SHA256WITHRSA":
                    return HashAlgorithmName.SHA256;
                case "SHA384WITHRSA":
                    return HashAlgorithmName.SHA384;
                case "SHA512WITHRSA":
                    return HashAlgorithmName.SHA512;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
        }

      
    }

    internal class SigCalculator : IStreamCalculator
    {
        private readonly RSA sig;
        private readonly HashAlgorithmName hashAlgorithmName;
        private readonly MemoryStream stream;

        internal SigCalculator(RSA sig, HashAlgorithmName hashAlgorithmName)
        {
            this.sig = sig;
            this.hashAlgorithmName = hashAlgorithmName;
            this.stream = new MemoryStream();
        }

        public Stream Stream
        {
            get { return stream; }
        }

        public object GetResult()
        {
            return new SigResult(sig, hashAlgorithmName, stream);
        }
    }

    internal class SigResult : IBlockResult
    {
        private readonly RSA privateKey;
        private readonly HashAlgorithmName hashAlgorithmName;
        private readonly MemoryStream stream;

        internal SigResult(RSA privateKey, HashAlgorithmName hashAlgorithmName, MemoryStream stream)
        {
            this.privateKey = privateKey;
            this.hashAlgorithmName = hashAlgorithmName;
            this.stream = stream;
        }

        public byte[] Collect()
        {
            return privateKey.SignData(stream.ToArray(), hashAlgorithmName, RSASignaturePadding.Pkcs1);
          
        }

        public int Collect(byte[] destination, int offset)
        {
            byte[] signature = Collect();

            Array.Copy(signature, 0, destination, offset, signature.Length);

            return signature.Length;
        }
    }
}

