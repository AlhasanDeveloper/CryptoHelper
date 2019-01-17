using CryptoHelper;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Signing_Sample
{
    /// <summary>
    /// This is a sample application to demonstrate how to sign and validate signature using CryptoHelper library.
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
            //Load the signing certificates
            X509Certificate2 privateKeySignature = new X509Certificate2(@"Certificates\eeSigning.pfx", "abc123", X509KeyStorageFlags.Exportable);
            X509Certificate2 publicKeySignature = new X509Certificate2(@"Certificates\eeSigning.cer", "");

            //Create the message that will be signed
            string message = "There is nothing that my blade cannot cut!";

            //Sign the message into base64 string
            string signedMessage = Crypto.SignData
            (
                Encoding.UTF8.GetBytes(message), privateKeySignature, HashAlgorithmName.SHA512
            );
            //Validate the signed message as base64 string
            bool validationStatus = Crypto.VerifyData
            (
                Encoding.UTF8.GetBytes(message), signedMessage, publicKeySignature, HashAlgorithmName.SHA512
            );

            //Sign message into byte array
            byte[] signedMessage2 = Crypto.SignDataByteArray
            (
                Encoding.UTF8.GetBytes(message), privateKeySignature, HashAlgorithmName.SHA512
            );
            //Validate the signed message as byte array
            bool validationStatus2 = Crypto.VerifyData
            (
                Encoding.UTF8.GetBytes(message), signedMessage2, publicKeySignature, HashAlgorithmName.SHA512
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
                    "Message: " + message + "\n" +
                    "Signature: " + ToHex(signedMessage2) + "\n" +
                    "Validation Status: " + validationStatus2.ToString()
            );

            Console.ReadKey();
        }
    }
}
