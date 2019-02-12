using CryptoHelper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateCreation_Sample
{
    /// <summary>
    /// This is a sample to demonstrate how to create certificates and CSR using CryptoHelper
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Export a public key to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        private static string ExportToPEM(X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        private static void Main(string[] args)
        {
            //Create a self signed certificate authority certificate
            X509Certificate2 ca = new X509Certificate2Builder
            {
                DistinguishedName = new DistinguishedNames
                {
                    commonName = "Selfsigned CA",
                    countryName = "KW",
                    localityName = "Hawally",
                    organizationalUnitName = "My Organization Unit",
                    organizationName = "My Organization"
                },
                SubjectAlternativeName = new SubjectAlternativeNames
                {
                    Rfc822Name = "me@example.com"
                },
                friendlyName = "My CA",
                keyPurpose = new string[] { BuilderKeyPurpose.AnyExtendedKeyUsage },
                keyUsage = BuilderKeyUsage.DigitalSignature | BuilderKeyUsage.CrlSign | BuilderKeyUsage.KeyCertSign,
                signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
                NotAfter = DateTime.Now.AddYears(10)
            }.Build();

            //Export CA to file
            Byte[] certData = ca.Export(X509ContentType.Pkcs12, "abc123");
            File.WriteAllBytes("CA.pfx", certData);
            File.WriteAllText("CA.cer", ExportToPEM(ca));

            //Use the created CA to create EE (End Entity) certificates

            //Exchange certificate creation
            X509Certificate2 eeExchange = new X509Certificate2Builder
            {
                DistinguishedName = new DistinguishedNames
                {
                    otherDN = new Dictionary<string, string>
                    {
                        { "CN", "My Name" },
                        { "C", "KW" },
                        { "O", "My Organization" },
                        { "OU", "My Organization Unit" },
                        { "L", "Hawally" },
                        { "E", "me@example.com" }
                    }
                },
                friendlyName = "My Exchange Certificate",
                Issuer = ca,
                Intermediate = false,
                keyPurpose = new string[] { },
                keyUsage = BuilderKeyUsage.DigitalSignature | BuilderKeyUsage.DataEncipherment,
                signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
                NotAfter = DateTime.Now.AddYears(10)
            }.Build();

            //Export the exchange certificate to file
            certData = eeExchange.Export(X509ContentType.Pkcs12, "abc123");
            File.WriteAllBytes("eeExchange.pfx", certData);
            File.WriteAllText("eeExchange.cer", ExportToPEM(eeExchange));

            //Signing certificate creation
            X509Certificate2 eeSigning = new X509Certificate2Builder
            {
                SubjectName = "CN=My Name, C=KW, O=My Organization, OU=My Organization Unit, L=Hawally, E=me@example.com",
                friendlyName = "My Signing Certificate",
                Issuer = ca,
                Intermediate = false,
                keyPurpose = new string[] { },
                keyUsage = BuilderKeyUsage.DigitalSignature,
                signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
                NotAfter = DateTime.Now.AddYears(10)
            }.Build();

            //Export the signing certificate to file
            certData = eeSigning.Export(X509ContentType.Pkcs12, "abc123");
            File.WriteAllBytes("eeSigning.pfx", certData);
            File.WriteAllText("eeSigning.cer", ExportToPEM(eeSigning));

            //Server authentication certificate creation
            X509Certificate2 serverAuth = new X509Certificate2Builder
            {
                DistinguishedName = new DistinguishedNames
                {
                    commonName = "www.example.com",
                    organizationName = "My Organization",
                    organizationalUnitName = "My Organization Unit",
                    localityName = "Hawally",
                    stateOrProvinceName = "Kuwait",
                    countryName = "KW"
                },
                SubjectAlternativeName = new SubjectAlternativeNames
                {
                    Rfc822Name = "me@example.com",
                    DnsName = new string[]
                    {
                        "www.example.com",
                        "example.com",
                        "api.example.com",
                        "ws.example.com",
                        "admin.example.com",
                        "you.example.com",
                    }
                },
                friendlyName = "My Server Certificate",
                Issuer = ca,
                Intermediate = false,
                keyPurpose = new string[] { BuilderKeyPurpose.IdKPServerAuth, BuilderKeyPurpose.IdKPClientAuth },
                criticalKeyPurpose = true,
                keyUsage = BuilderKeyUsage.DigitalSignature | BuilderKeyUsage.KeyEncipherment,
                criticalKeyUsage = true,
                signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
                NotAfter = DateTime.Now.AddYears(10)
            }.Build();

            //Export the server authentication certificate to file
            certData = serverAuth.Export(X509ContentType.Pkcs12, "abc123");
            File.WriteAllBytes("serverAuth.pfx", certData);
            File.WriteAllText("serverAuth.cer", ExportToPEM(serverAuth));

            //Create CSR (certificate signing request)
            X509Certificate2Builder.CSR csr = new X509Certificate2Builder
            {
                //SubjectName = "CN=My Name, C=KW, O=My Organization, OU=My Organization Unit, L=Hawally, E=me@example.com",
                DistinguishedName = new DistinguishedNames
                {
                    commonName = "My Name",
                    countryName = "KW",
                    organizationName = "My Organization",
                    organizationalUnitName = "My Organization Unit",
                    localityName = "Hawally",
                },
                SubjectAlternativeName = new SubjectAlternativeNames
                {
                    Rfc822Name = "me@example.com"
                },
                friendlyName = "My Friendly Name",
                keyPurpose = new string[] { },
                keyUsage = BuilderKeyUsage.DigitalSignature,
                signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
                NotAfter = DateTime.Now.AddYears(10)
            }.GenerateCSR();
            certData = csr.PrivateKey.Export(X509ContentType.Pkcs12, "abc123");
            File.WriteAllBytes("csrPrivateKey.pfx", certData);
            File.WriteAllText("csrPrivateKey.cer", ExportToPEM(csr.PrivateKey));
            File.WriteAllText("csr.csr", csr.CSRPEM);
        }
    }
}