using CryptoHelper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace XMLSigning_Sample
{
    /// <summary>
    /// This is a sample application to demonstrate how to sign and validate XML signature using CryptoHelper library.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            //Load the signing certificates
            X509Certificate2 privateKeySignature = new X509Certificate2(@"Certificates\eeSigning.pfx", "abc123", X509KeyStorageFlags.Exportable);
            X509Certificate2 publicKeySignature = new X509Certificate2(@"Certificates\eeSigning.cer", "");

            //Load XML document to be signed
            string xmlData = File.ReadAllText(@"XMLDocuments\cd_catalog.xml");
            //Sign the XML document
            string signedXMLData = Crypto.SignXml(xmlData, privateKeySignature, true);
            //Output the signed XML to file
            File.WriteAllText(@"XMLDocuments\cd_catalog_SIGNED.xml", signedXMLData);

            //Read a signed XML document
            signedXMLData = File.ReadAllText(@"XMLDocuments\cd_catalog_SIGNED.xml");
            //Validate the signed XML document using the embedded key in it
            Console.WriteLine("Verifying XML using internal signature STATUS = " + Crypto.VerifyXml(signedXMLData));
            //Validate the signed XML document using external certificate
            Console.WriteLine("Verifying XML using publicKey STATUS = " + Crypto.VerifyXml(signedXMLData, publicKeySignature));

            Console.WriteLine("\n*********************************\n");

            //Read the SAML request to be validate
            xmlData = File.ReadAllText(@"XMLDocuments\saml.xml");
            //Validate the SAML request using its embedded certificate
            Console.WriteLine("Verifying SAML using internal signature STATUS = " + Crypto.VerifyXml(xmlData));

            Console.ReadKey();
        }
    }
}
