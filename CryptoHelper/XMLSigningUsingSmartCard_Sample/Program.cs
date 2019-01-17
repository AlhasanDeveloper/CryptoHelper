using CryptoHelper;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace XMLSigningUsingSmartCard_Sample
{
    /// <summary>
    /// This is a sample application to demonstrate how to sign and validate XML signature using smart card in CryptoHelper library.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            //Fetch certificates in the currently connected card
            List<X509Certificate2> cardCertificates = new List<X509Certificate2>();
            try
            {
                cardCertificates.AddRange(BaseSmartCardCryptoProvider.GetCertificates());
            }
            catch (Win32Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            X509Certificate2 digitalSignatureCertificate = null;

            //Get the certificate that has non repudiation key usage as it is the digital signature key for the Kuwaiti civil id
            foreach (X509Certificate2 x509 in cardCertificates)
            {
                foreach (X509Extension extension in x509.Extensions)
                {
                    //OID 2.5.29.15 is for key usage
                    if (extension.Oid.Value.Equals("2.5.29.15"))
                    {
                        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                        if (((ext.KeyUsages & X509KeyUsageFlags.NonRepudiation) | (ext.KeyUsages & X509KeyUsageFlags.DigitalSignature)) == (X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DigitalSignature))
                        {
                            digitalSignatureCertificate = x509;
                        }
                    }
                }
            }

            //See if digital signature certificate was found
            if (digitalSignatureCertificate != null)
            {
                //Export the public key which will be used in validation
                X509Certificate2 publicKeySigning = new X509Certificate2(digitalSignatureCertificate.Export(X509ContentType.Cert));

                //Read the pin
                Console.Write("Please enter your pin: ");
                string pin = Console.ReadLine();

                //Load XML document to be signed
                string xmlData = File.ReadAllText(@"XMLDocuments\cd_catalog.xml");
                //Sign the XML document
                string signedXMLData = Crypto.SignXml(xmlData, digitalSignatureCertificate, true, pin);
                //Output the signed XML to file
                File.WriteAllText(@"XMLDocuments\cd_catalog_SIGNED.xml", signedXMLData);

                //Read a signed XML document
                signedXMLData = File.ReadAllText(@"XMLDocuments\cd_catalog_SIGNED.xml");
                //Validate the signed XML document using the embedded key in it
                Console.WriteLine("Verifying XML using internal signature STATUS = " + Crypto.VerifyXml(signedXMLData));
                //Validate the signed XML document using external certificate
                Console.WriteLine("Verifying XML using publicKey STATUS = " + Crypto.VerifyXml(signedXMLData, publicKeySigning));
            }
            Console.ReadKey();
        }
    }
}
