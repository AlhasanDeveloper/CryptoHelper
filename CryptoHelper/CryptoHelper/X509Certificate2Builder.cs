using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoHelper
{
    /// <summary>
    /// OID list for certificate key purpose
    /// </summary>
    public class BuilderKeyPurpose
    {
        private static readonly string id_kp = "1.3.6.1.5.5.7.3";
        public static readonly string AnyExtendedKeyUsage = "2.5.29.37.0";
        public static readonly string IdKPClientAuth = id_kp + ".2";
        public static readonly string IdKPCodeSigning = id_kp + ".3";
        public static readonly string IdKPEmailProtection = id_kp + ".4";
        public static readonly string IdKPIpsecEndSystem = id_kp + ".5";
        public static readonly string IdKPIpsecTunnel = id_kp + ".6";
        public static readonly string IdKPIpsecUser = id_kp + ".7";
        public static readonly string IdKPOcspSigning = id_kp + ".8";
        public static readonly string IdKPServerAuth = id_kp + ".1";
        public static readonly string IdKPDVCS = id_kp + ".10";
        public static readonly string IdKPsbgpCertAAServerAuth = id_kp + ".11";
        public static readonly string IdKPSCVPResponder = id_kp + ".12";
        public static readonly string IdKPEAPOverPPP = id_kp + ".13";
        public static readonly string IdKPEAPOverLAN = id_kp + ".14";
        public static readonly string IdKPSCVPServer = id_kp + ".15";
        public static readonly string IdKPSCVPClient = id_kp + ".16";
        public static readonly string IdKPIpsecIKE = id_kp + ".17";
        public static readonly string IdKPSmartCardLogon = "1.3.6.1.4.1.311.20.2.2";
    }

    /// <summary>
    /// Flag list for certificate key usages
    /// </summary>
    public class BuilderKeyUsage
    {
        public const int CrlSign = 2;
        public const int DataEncipherment = 16;
        public const int DecipherOnly = 32768;
        public const int DigitalSignature = 128;
        public const int EncipherOnly = 1;
        public const int KeyAgreement = 8;
        public const int KeyCertSign = 4;
        public const int KeyEncipherment = 32;
        public const int NonRepudiation = 64;
    }

    /// <summary>
    /// Enumerator to chose from the allowed list, if choice not valid then SHA256WITHRSA will be the default
    /// </summary>
    public enum PKCS15SignatureAlgorithm
    {
        MD2WITHRSA,
        MD5WITHRSA,
        SHA1WithRSA,
        SHA224WITHRSA,
        SHA256WITHRSA,
        SHA384WITHRSA,
        SHA512WITHRSA
    };

    /// <summary>
    /// Class used to insert the desired DN into the certificate creation.
    /// </summary>
    public class DistinguishedNames
    {
        public string commonName { set; get; }
        public string localityName { set; get; }
        public string stateOrProvinceName { set; get; }
        public string organizationName { set; get; }
        public string organizationalUnitName { set; get; }
        public string countryName { set; get; }
        public string streetAddress { set; get; }
        public string userId { set; get; }
        public string[] domainComponent { set; get; }

        [Obsolete("Use Rfc822Name in SubjectAlternativeNames instead")]
        public string emailAddress { set; get; }

        /// <summary>
        /// Insert valid distinguished name (DN) in it as key and the value as the DN value.
        /// </summary>
        public Dictionary<string, string> otherDN { set; get; }
    };

    /// <summary>
    /// Class used to insert the desired SAN into the certificate creation.
    /// </summary>
    public class SubjectAlternativeNames
    {
        public string[] DnsName { set; get; }
        public string[] IPAddress { set; get; }

        /// <summary>
        /// Email.
        /// </summary>
        public string Rfc822Name { set; get; }
    };

    /// <summary>
    /// Class for building certificate.
    /// </summary>
    public class X509Certificate2Builder
    {
        /// <summary>
        /// Certificate subject name for example "CN=My Name, C=KW, O=My Organization, OU=My Organization Unit".
        /// </summary>
        [Obsolete("Not needed if DistinguishedName has been set")]
        public string SubjectName
        { set { _subjectName = value; } }

        /// <summary>
        /// Object to set the subject name easily.
        /// </summary>
        public DistinguishedNames DistinguishedName
        { set { _DistinguishedName = value; } }

        /// <summary>
        /// Used to set subject alternative names to the certificate.
        /// </summary>
        public SubjectAlternativeNames SubjectAlternativeName
        { set { _SubjectAlternativeName = value; } }

        /// <summary>
        /// Certificate issuer name (no need to use it in case Issuer is used).
        /// </summary>
        [Obsolete("Not needed if Issuer certificate has been set")]
        public string IssuerName
        { set { _issuerName = value; } }

        /// <summary>
        /// Private key of the issuer (no need to use it in case Issuer is used).
        /// </summary>
        [Obsolete("Not needed if Issuer certificate has been set")]
        public AsymmetricAlgorithm IssuerPrivateKey
        { set { _issuerPrivateKey = value; } }

        /// <summary>
        /// Sets the Issuer certificate and sets from this certificate the IssuerName and IssuerPrivateKey.
        /// </summary>
        public X509Certificate2 Issuer
        {
            set
            {
                _issuer = value;
                _issuerName = value.IssuerName.Decode(X500DistinguishedNameFlags.UseCommas | X500DistinguishedNameFlags.DoNotUsePlusSign | X500DistinguishedNameFlags.DoNotUseQuotes);
                string[] dn = _issuerName.Split(',');

                //remove first white space
                for (int i = 1; i < dn.Length; i++)
                {
                    if (dn[i].Length > 0)
                        dn[i] = dn[i].Remove(0, 1);
                }

                StringBuilder sb = new StringBuilder();

                //Convert friendly names to OID
                foreach (string s in dn)
                {
                    string[] nv = s.Split('=');
                    if (nv.Length > 1)
                    {
                        Oid q = Oid.FromFriendlyName(nv[0], OidGroup.All);
                        sb.Append(q.Value).Append("=").Append(nv[1]).Append(",");
                    }
                }
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    _issuerName = sb.ToString();
                }
                if (value.HasPrivateKey)
                    _issuerPrivateKey = value.PrivateKey;
            }
        }

        /// <summary>
        /// List of OIDs used to define the certificate key purpose use class BuilderKeyPurpose for commonly used OIDs.
        /// </summary>
        public string[] keyPurpose
        { set { _keyPurpose = value; } }

        /// <summary>
        /// Bit field to define the key usages use class BuilderKeyUsage and use bitwise operation OR to use the fields.
        /// </summary>
        public int keyUsage
        { set { _keyUsage = value; } }

        /// <summary>
        /// Key strength of the public key default is 2048.
        /// </summary>
        public int? KeyStrength
        { set { _keyStrength = value ?? 2048; } }

        /// <summary>
        /// Certificate start date, default is current date.
        /// </summary>
        public DateTime? NotBefore
        { set { _notBefore = value; } }

        /// <summary>
        /// Certificate expiration date, default is 2 years from current date.
        /// </summary>
        public DateTime? NotAfter
        { set { _notAfter = value; } }

        /// <summary>
        /// Flag to set the certificate as an intermediate card authority.
        /// </summary>
        public bool Intermediate
        { set { _intermediate = value; } }

        /// <summary>
        /// Friendly name for the generated certificate.
        /// </summary>
        public string friendlyName
        { set { _friendlyName = value; } }

        /// <summary>
        /// The signature algorithm for the certificate, default is "SHA256WithRSA".
        /// </summary>
        public PKCS15SignatureAlgorithm signatureAlgorithm
        { set { _signatureAlgorithm = value; } }

        /// <summary>
        /// Sets a value indicating whether the key usage is critical or not.
        /// </summary>
        public bool criticalKeyUsage
        { set { _criticalKeyUsage = value; } }

        /// <summary>
        /// Sets a value indicating whether the key purpose is critical or not.
        /// </summary>
        public bool criticalKeyPurpose
        { set { _criticalKeyPurpose = value; } }

        private string _subjectName;
        private DistinguishedNames _DistinguishedName = null;
        private SubjectAlternativeNames _SubjectAlternativeName = null;
        private X509Certificate2 _issuer;
        private string _issuerName;
        private AsymmetricAlgorithm _issuerPrivateKey;
        private int _keyStrength = 2048;
        private DateTime? _notBefore;
        private DateTime? _notAfter;
        private bool _intermediate = true;
        private string[] _keyPurpose = new string[] { KeyPurposeID.AnyExtendedKeyUsage.Id };
        private int _keyUsage = 0;
        private string _friendlyName = null;
        private PKCS15SignatureAlgorithm _signatureAlgorithm = PKCS15SignatureAlgorithm.SHA256WITHRSA;
        private bool _criticalKeyUsage = false;
        private bool _criticalKeyPurpose = false;

        /// <summary>
        /// Converts DistinguishedNames to X509Name
        /// </summary>
        /// <param name="dn">Distinguished names that were filled by user</param>
        /// <returns>X509Name to be used in certificate builder</returns>
        private X509Name DistinguishedNamesToX509Name(DistinguishedNames dn)
        {
            StringBuilder builder = new StringBuilder();

            if (dn.otherDN != null && dn.otherDN.Count > 0)
            {
                foreach (string key in dn.otherDN.Keys)
                {
                    builder.Append(Oid.FromFriendlyName(key, OidGroup.All).Value).Append("=").Append(dn.otherDN[key]).Append(",");
                }
            }
            if (dn.domainComponent != null && dn.domainComponent.Length > 0)
            {
                foreach (string dc in dn.domainComponent)
                {
                    builder.Append("0.9.2342.19200300.100.1.25=").Append(dc).Append(",");
                }
            }
            if (dn.countryName != null && dn.countryName.Length > 0)
            {
                builder.Append("2.5.4.6=").Append(dn.countryName).Append(",");
            }
            if (dn.stateOrProvinceName != null && dn.stateOrProvinceName.Length > 0)
            {
                builder.Append("2.5.4.8=").Append(dn.stateOrProvinceName).Append(",");
            }
            if (dn.localityName != null && dn.localityName.Length > 0)
            {
                builder.Append("2.5.4.7=").Append(dn.localityName).Append(",");
            }
            if (dn.streetAddress != null && dn.streetAddress.Length > 0)
            {
                builder.Append("2.5.4.9=").Append(dn.streetAddress).Append(",");
            }
            if (dn.organizationName != null && dn.organizationName.Length > 0)
            {
                builder.Append("2.5.4.10=").Append(dn.organizationName).Append(",");
            }
            if (dn.organizationalUnitName != null && dn.organizationalUnitName.Length > 0)
            {
                builder.Append("2.5.4.11=").Append(dn.organizationalUnitName).Append(",");
            }
            if (dn.emailAddress != null && dn.emailAddress.Length > 0)
            {
                builder.Append("1.2.840.113549.1.9.1=").Append(dn.emailAddress).Append(",");
            }
            if (dn.userId != null && dn.userId.Length > 0)
            {
                builder.Append("0.9.2342.19200300.100.1.1=").Append(dn.userId).Append(",");
            }
            if (dn.commonName != null && dn.commonName.Length > 0)
            {
                builder.Append("2.5.4.3=").Append(dn.commonName).Append(",");
            }

            //Remove the last coma
            if (builder.Length > 0)
            {
                builder.Remove(builder.Length - 1, 1);
            }

            return new X509Name(builder.ToString());
        }

        private GeneralNames SubjectAlternativeNamesToGeneralNames(SubjectAlternativeNames san)
        {
            List<GeneralName> sanList = new List<GeneralName>();
            if (san.Rfc822Name != null && san.Rfc822Name.Length > 0)
            {
                sanList.Add(new GeneralName(GeneralName.Rfc822Name, san.Rfc822Name));
            }
            if (san.DnsName != null && san.DnsName.Length > 0)
            {
                foreach (string dns in san.DnsName)
                {
                    sanList.Add(new GeneralName(GeneralName.DnsName, dns));
                }
            }
            if (san.IPAddress != null && san.IPAddress.Length > 0)
            {
                foreach (string ip in san.IPAddress)
                {
                    sanList.Add(new GeneralName(GeneralName.IPAddress, ip));
                }
            }
            return new GeneralNames(sanList.ToArray());
        }

        /// <summary>
        /// Builds the certificate depending on the parameters
        /// </summary>
        /// <returns>X509Certificate2 from the chosen parameters</returns>
        public X509Certificate2 Build()
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            if (_signatureAlgorithm < 0 || (int)_signatureAlgorithm >= PKCS15SignatureAlgorithmList.Length)
                _signatureAlgorithm = PKCS15SignatureAlgorithm.SHA256WITHRSA;

            // Add SAN Extension
            if (_SubjectAlternativeName != null)
            {
                certificateGenerator.AddExtension
                (
                    X509Extensions.SubjectAlternativeName,
                    false,
                    SubjectAlternativeNamesToGeneralNames(_SubjectAlternativeName)
                );
            }

            // Issuer and Subject Name
            if (_DistinguishedName == null)
            {
                certificateGenerator.SetIssuerDN(new X509Name(_issuerName ?? _subjectName));
                certificateGenerator.SetSubjectDN(new X509Name(_subjectName));
            }
            else
            {
                if (_issuerName != null && _issuerName.Length > 0)
                {
                    certificateGenerator.SetIssuerDN(new X509Name(_issuerName));
                }
                else
                {
                    certificateGenerator.SetIssuerDN(DistinguishedNamesToX509Name(_DistinguishedName));
                }
                certificateGenerator.SetSubjectDN(DistinguishedNamesToX509Name(_DistinguishedName));
            }

            // Authority Key Identifier
            if (_issuer != null)
            {
                var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(
                    DotNetUtilities.FromX509Certificate(_issuer)
                );
                certificateGenerator.AddExtension(
                    X509Extensions.AuthorityKeyIdentifier.Id,
                    false,
                    authorityKeyIdentifier
                );
            }

            // Basic Constraints - certificate is allowed to be used as intermediate.
            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints.Id, true, new BasicConstraints(_intermediate));

            // Key intended purpose constrain
            if (_keyPurpose.Length > 0)
            {
                ArrayList kpList = new ArrayList();
                for (int i = 0; i < _keyPurpose.Length; i++)
                {
                    kpList.Add(new DerObjectIdentifier(_keyPurpose[i]));
                }
                IEnumerable kp = kpList;
                certificateGenerator.AddExtension(
                    X509Extensions.ExtendedKeyUsage.Id,
                    _criticalKeyPurpose,
                    new ExtendedKeyUsage(kp)
                );
            }

            // Key usage
            if (_keyUsage > 0)
            {
                certificateGenerator.AddExtension(
                    X509Extensions.KeyUsage.Id,
                    _criticalKeyUsage,
                    new KeyUsage(_keyUsage)
                );
            }

            // Valid For
            certificateGenerator.SetNotBefore(_notBefore ?? DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(_notAfter ?? DateTime.UtcNow.Date.AddYears(2));

            // Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, _keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            var issuerKeyPair = _issuerPrivateKey == null
                ? subjectKeyPair
                : DotNetUtilities.GetKeyPair(_issuerPrivateKey);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // self-sign certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PKCS15SignatureAlgorithmList[(int)_signatureAlgorithm], issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);

            // merge into X509Certificate2
            if (_friendlyName != null)
            {
                return new X509Certificate2(certificate.GetEncoded())
                {
                    PrivateKey = ConvertToRsaPrivateKey(subjectKeyPair),
                    FriendlyName = _friendlyName
                };
            }
            return new X509Certificate2(certificate.GetEncoded())
            {
                PrivateKey = ConvertToRsaPrivateKey(subjectKeyPair)
            };
        }

        /// <summary>
        /// Builds the CSR depending on the parameters provided.
        /// </summary>
        /// <returns>CSR data.</returns>
        public CSR GenerateCSR()
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            if (_signatureAlgorithm < 0 || (int)_signatureAlgorithm >= PKCS15SignatureAlgorithmList.Length)
                _signatureAlgorithm = PKCS15SignatureAlgorithm.SHA256WITHRSA;
            
            // Issuer and Subject Name
            if (_DistinguishedName == null)
            {
                certificateGenerator.SetIssuerDN(new X509Name(_subjectName));
                certificateGenerator.SetSubjectDN(new X509Name(_subjectName));
            }
            else
            {
                certificateGenerator.SetIssuerDN(DistinguishedNamesToX509Name(_DistinguishedName));
                certificateGenerator.SetSubjectDN(DistinguishedNamesToX509Name(_DistinguishedName));
            }

            // Add SAN extension
            if (_SubjectAlternativeName != null)
            {
                certificateGenerator.AddExtension
                (
                    X509Extensions.SubjectAlternativeName,
                    false,
                    SubjectAlternativeNamesToGeneralNames(_SubjectAlternativeName)
                );
            }

            // Basic Constraints - certificate is not allowed to be used as intermediate.
            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints.Id, true, new BasicConstraints(false));

            // Key intended purpose constrain
            if (_keyPurpose.Length > 0)
            {
                ArrayList kpList = new ArrayList();
                for (int i = 0; i < _keyPurpose.Length; i++)
                {
                    kpList.Add(new DerObjectIdentifier(_keyPurpose[i]));
                }
                IEnumerable kp = kpList;
                certificateGenerator.AddExtension(
                    X509Extensions.ExtendedKeyUsage.Id,
                    _criticalKeyPurpose,
                    new ExtendedKeyUsage(kp)
                );
            }

            // Key usage
            if (_keyUsage > 0)
            {
                certificateGenerator.AddExtension(
                    X509Extensions.KeyUsage.Id,
                    _criticalKeyUsage,
                    new KeyUsage(_keyUsage)
                );
            }

            // Valid For
            certificateGenerator.SetNotBefore(_notBefore ?? DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(_notAfter ?? DateTime.UtcNow.Date.AddYears(2));

            // Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, _keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            var issuerKeyPair = _issuerPrivateKey == null
                ? subjectKeyPair
                : DotNetUtilities.GetKeyPair(_issuerPrivateKey);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            //Generate CSR
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PKCS15SignatureAlgorithmList[(int)_signatureAlgorithm], issuerKeyPair.Private, random);
            Pkcs10CertificationRequest certificationRequest = null;
            if (_DistinguishedName == null)
            {
                certificationRequest = new Pkcs10CertificationRequest(signatureFactory, new X509Name(_subjectName), subjectKeyPair.Public, null);
            }
            else
            {
                certificationRequest = new Pkcs10CertificationRequest(signatureFactory, DistinguishedNamesToX509Name(_DistinguishedName), subjectKeyPair.Public, null);
            }
            var certificate = certificateGenerator.Generate(signatureFactory);

            //Build the CSR
            StringBuilder csrStrBuilder = new StringBuilder();
            PemWriter csrPemWriter = new PemWriter(new StringWriter(csrStrBuilder));
            csrPemWriter.WriteObject(certificationRequest);
            csrPemWriter.Writer.Flush();

            CSR csrResult = new CSR();
            csrResult.CSRPEM = csrStrBuilder.ToString();

            //Merge the private key into X509Certificate2
            X509Certificate2 privateKey;
            if (_friendlyName != null)
            {
                privateKey = new X509Certificate2(certificate.GetEncoded())
                {
                    PrivateKey = ConvertToRsaPrivateKey(subjectKeyPair),
                    FriendlyName = _friendlyName
                };
            }
            else
            {
                privateKey = new X509Certificate2(certificate.GetEncoded())
                {
                    PrivateKey = ConvertToRsaPrivateKey(subjectKeyPair)
                };
            }
            csrResult.PrivateKey = privateKey;

            return csrResult;
        }

        /// <summary>
        /// CSR container which holds the CSR to be sent and the generated private key.
        /// </summary>
        public class CSR
        {
            public X509Certificate2 PrivateKey { set; get; }
            public string CSRPEM { set; get; }
        }

        /// <summary>
        /// Converts to RSA private key.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <returns></returns>
        /// <exception cref="PemException">malformed sequence in RSA private key.</exception>
        private static AsymmetricAlgorithm ConvertToRsaPrivateKey(AsymmetricCipherKeyPair keyPair)
        {
            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(keyInfo.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            var rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                rsa.Exponent2, rsa.Coefficient);

            return DotNetUtilities.ToRSA(rsaparams);
        }

        /// <summary>
        /// List of signature algorithms
        /// </summary>
        private static string[] PKCS15SignatureAlgorithmList =
        {
            "MD2WITHRSA",
            "MD5WITHRSA",
            "SHA1WITHRSA",
            "SHA224WITHRSA",
            "SHA256WITHRSA",
            "SHA384WITHRSA",
            "SHA512WITHRSA",
        };
    }
}
