using CryptoHelper;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EncryptionDecryption_Sample
{
    /// <summary>
    /// This is a sample to demonstrate how to encrypt and decrypt using CryptoHelper.
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
            //Load certificate used for exchange
            X509Certificate2 privateKeyExchange = new X509Certificate2(@"Certificates\eeExchange.pfx", "abc123", X509KeyStorageFlags.Exportable);
            X509Certificate2 publicKeyExchange = new X509Certificate2(privateKeyExchange.Export(X509ContentType.Cert));

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
                    encryptedMessage, privateKeyExchange, RSAEncryptionPadding.OaepSHA1
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
                encryptedMessage2, privateKeyExchange, RSAEncryptionPadding.OaepSHA1
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

            Console.ReadKey();
        }
    }
}
