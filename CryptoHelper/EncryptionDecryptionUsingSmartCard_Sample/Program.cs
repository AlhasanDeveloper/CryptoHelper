using CryptoHelper;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EncryptionDecryptionUsingSmartCard_Sample
{
    /// <summary>
    /// This is a sample to demonstrate how to encrypt and decrypt using smart card in PACICrypto library.
    /// </summary>
    internal class Program
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

        private static void Main(string[] args)
        {
            Crypto crypto = new Crypto();

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
                //Export the public key which will be used in encrypting
                X509Certificate2 publicKeyExchange = new X509Certificate2(digitalSignatureCertificate.Export(X509ContentType.Cert));

                //Read the pin
                Console.Write("Please enter your pin: ");
                string pin = Console.ReadLine();

                //This is the message that will be used in the encryption and decryption process
                string message = "There is nothing that my blade cannot cut!";

                //Encrypt the message as a Base64 encoded string
                string encryptedMessage = Crypto.Encrypt
                (
                    Encoding.UTF8.GetBytes(message), publicKeyExchange, RSAEncryptionPadding.OaepSHA1
                );
                //Decrypt the Base64 encoded encrypted message
                string decryptedMessage = Encoding.UTF8.GetString
                (
                    Crypto.Decrypt
                    (
                        encryptedMessage, digitalSignatureCertificate, RSAEncryptionPadding.OaepSHA1, pin
                    )
                );

                //Encrypt the message as raw data
                byte[] encryptedMessage2 = Crypto.EncryptToByteArray
                (
                    Encoding.UTF8.GetBytes(message), publicKeyExchange, RSAEncryptionPadding.OaepSHA1
                );
                //Decrypt the raw data
                string decryptedMessage2 = Encoding.UTF8.GetString(Crypto.Decrypt
                (
                    encryptedMessage2, digitalSignatureCertificate, RSAEncryptionPadding.OaepSHA1, pin
                ));

                //Output the results
                Console.WriteLine
                (
                    "Message: " + message + "\n" +
                    "Encrypted: " + encryptedMessage + "\n" +
                    "Decrypted: " + decryptedMessage
                );
                Console.WriteLine("\n*********************************\n");
                Console.WriteLine
                (
                    "Message: " + message + "\n" +
                    "Encrypted: " + ToHex(encryptedMessage2) + "\n" +
                    "Decrypted: " + decryptedMessage2
                );
            }

            Console.ReadKey();
        }
    }
}