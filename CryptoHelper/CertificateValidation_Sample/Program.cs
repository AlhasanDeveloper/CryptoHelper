using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificateValidation_Sample
{
    /// <summary>
    /// This is a sample application to demonstrate how to validate a certificate using the CryptoHelper library.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            //Load the certificate to be validated.
            X509Certificate2 sampleCert = new X509Certificate2(@"certificate\DigiCert.cer", "");
            //Load the issuer certificate of the certificate to be validated.
            X509Certificate2 sampleCertIssuer = new X509Certificate2(@"certificate\VeriSign.cer", "");
            bool ocspSample = false;
            bool crlSample = false;
            try
            {
                //Validate using OCSP.
                ocspSample = Crypto.ValidateCertificateWithOCSP(sampleCert, sampleCertIssuer);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            try
            {
                //Validate using CRL.
                crlSample = Crypto.ValidateCertificateWithCRL(sampleCert, sampleCertIssuer, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            //Output the results.
            Console.WriteLine
            (
                "Sample OCSP Status: " + ocspSample + "\n" +
                "Sample CRL Status: " + crlSample + "\n"
            );

            Console.ReadKey();
        }
    }
}
