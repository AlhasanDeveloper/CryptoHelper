using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SigningUsingSmartCard_Sample
{
    /// <summary>
    /// This is a sample application to demonstrate how to sign and validate signature using smart card in CryptoHelper library.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Converts the byte array to a hex string
        /// </summary>
        /// <param name="value">byte array value</param>
        /// <returns>hex string representation of the byte array value</returns>
        private static StringBuilder ToHex(byte[] value)
        {
            StringBuilder builder = new StringBuilder();
            if (value != null)
            {
                foreach (byte num in value)
                {
                    builder.Append(num.ToString("X2"));
                }
            }
            return builder;
        }

        static void Main(string[] args)
        {
            //Fetch certificates in the currently connected card
            List<X509Certificate2> cardCertificates = BaseSmartCardCryptoProvider.GetCertificates();
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

                //Create the message that will be signed
                string message = "There is nothing that my blade cannot cut!";

                //Read the pin
                Console.Write("Please enter your pin: ");
                string pin = Console.ReadLine();

                //Sign the data
                string signedMessage = Crypto.SignData
                (
                    Encoding.UTF8.GetBytes(message),
                    digitalSignatureCertificate,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1,
                    pin
                );

                //Verify the signed data
                bool validationStatus = Crypto.VerifyData
                (
                    Encoding.UTF8.GetBytes(message), signedMessage, publicKeySigning, HashAlgorithmName.SHA256
                );

                //Create the hash
                byte[] hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(message));

                //Sign the data
                string signedHash = Crypto.SignHash
                (
                    hash,
                    digitalSignatureCertificate,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1,
                    pin
                );

                //Verify the signed data
                bool validationStatus2 = Crypto.VerifyHash
                (
                    hash, signedHash, publicKeySigning, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1
                );

                //Output the results
                Console.WriteLine
                (
                        "Message: " + message + "\n" +
                        "Signature: " + signedMessage + "\n" +
                        "Validation Status: " + validationStatus.ToString()
                );
                Console.WriteLine("\n*********************************\n");
                Console.WriteLine
                (
                        "Hash: " + ToHex(hash) + "\n" +
                        "Signature: " + signedHash + "\n" +
                        "Validation Status: " + validationStatus2.ToString()
                );
            }

            Console.ReadKey();
        }
    }
}
