using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoHelper
{
    internal class CertificateCrypto
    {
        /// <summary>
        /// Encrypts the message using an exchange public key
        /// </summary>
        /// <param name="message">Message to be encrypted</param>
        /// <param name="publicKey">Public exchange key to encrypt the message</param>
        /// <param name="padding">Padding mode to be used with the encryption</param>
        /// <returns>Encrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] Encrypt(byte[] message, X509Certificate2 publicKey, RSAEncryptionPadding padding)
        {
            byte[] resp = null;
            try
            {
                RSAParameters Params = publicKey.GetRSAPublicKey().ExportParameters(false);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(Params);
                    byte[] encryptedMessage = rsa.Encrypt(message, padding);
                    resp = encryptedMessage;
                }
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }

            return resp;
        }

        /// <summary>
        /// Decrypts the message using an exchange private key
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message as base64 string to be decrypted</param>
        /// <param name="privateKey">Private exchange key to decrypt the message</param>
        /// <param name="padding">Padding mode to be used with the decryption</param>
        /// <returns>Decrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        /// <exception cref="FormatException">The length of string, ignoring white-space characters, is not zero or a multiple of 4. -or-The format of s is invalid. string contains a non-base-64 character, more than two padding characters, or a non-white space-character among the padding characters.</exception>
        public static byte[] Decrypt(string encryptedMessage, X509Certificate2 privateKey, RSAEncryptionPadding padding)
        {
            byte[] resp = null;
            try
            {
                RSAParameters Params = privateKey.GetRSAPrivateKey().ExportParameters(true);
                if (privateKey.HasPrivateKey)
                {
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(Params);
                        byte[] decodedEncryptedBytes = Convert.FromBase64String(encryptedMessage);
                        resp = rsa.Decrypt(decodedEncryptedBytes, padding);
                    }
                }
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (FormatException ex)
            {
                throw ex;
            }
            return resp;
        }

        /// <summary>
        /// Decrypts the message using an exchange private key that has a pin.
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message as base64 string to be decrypted</param>
        /// <param name="privateKey">Private exchange key to decrypt the message</param>
        /// <param name="padding">Padding mode to be used with the decryption</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Decrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        /// <exception cref="FormatException">The length of string, ignoring white-space characters, is not zero or a multiple of 4. -or-The format of s is invalid. string contains a non-base-64 character, more than two padding characters, or a non-white space-character among the padding characters.</exception>
        public static byte[] Decrypt(string encryptedMessage, X509Certificate2 privateKey, RSAEncryptionPadding padding, string pin)
        {
            try
            {
                byte[] decodedEncryptedBytes = Convert.FromBase64String(encryptedMessage);
                RSA rsa = privateKey.GetRSAPrivateKey();
                RSACng rsaCng = rsa as RSACng;
                if (rsaCng != null)
                {
                    // Set the PIN, an explicit null terminator is required to this Unicode/UCS-2 string.

                    byte[] propertyBytes;

                    if (pin[pin.Length - 1] == '\0')
                    {
                        propertyBytes = Encoding.Unicode.GetBytes(pin);
                    }
                    else
                    {
                        propertyBytes = new byte[Encoding.Unicode.GetByteCount(pin) + 2];
                        Encoding.Unicode.GetBytes(pin, 0, pin.Length, propertyBytes, 0);
                    }

                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    CngProperty pinProperty = new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None);

                    rsaCng.Key.SetProperty(pinProperty);
                    return rsaCng.Decrypt(decodedEncryptedBytes, padding);
                }
                throw new CryptographicException("The key is not compatible with Cryptography Next Generation (CNG)");
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (ArgumentNullException ex)
            {
                throw ex;
            }
            catch (FormatException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts the message using an exchange private key.
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message as byte array</param>
        /// <param name="privateKey">Private exchange key to decrypt the message</param>
        /// <param name="padding">Padding mode to be used with the decryption</param>
        /// <returns>Decrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] Decrypt(byte[] encryptedMessage, X509Certificate2 privateKey, RSAEncryptionPadding padding)
        {
            byte[] resp = null;
            try
            {
                RSAParameters Params = privateKey.GetRSAPrivateKey().ExportParameters(true);
                if (privateKey.HasPrivateKey)
                {
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(Params);
                        resp = rsa.Decrypt(encryptedMessage, padding);
                    }
                }
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            return resp;
        }

        /// <summary>
        /// Decrypts the message using an exchange private key that has a pin.
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message as byte array</param>
        /// <param name="privateKey">Private exchange key to decrypt the message</param>
        /// <param name="padding">Padding mode to be used with the decryption</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Decrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static byte[] Decrypt(byte[] encryptedMessage, X509Certificate2 privateKey, RSAEncryptionPadding padding, string pin)
        {
            try
            {
                RSA rsa = privateKey.GetRSAPrivateKey();
                RSACng rsaCng = rsa as RSACng;
                if (rsaCng != null)
                {
                    // Set the PIN, an explicit null terminator is required to this Unicode/UCS-2 string.

                    byte[] propertyBytes;

                    if (pin[pin.Length - 1] == '\0')
                    {
                        propertyBytes = Encoding.Unicode.GetBytes(pin);
                    }
                    else
                    {
                        propertyBytes = new byte[Encoding.Unicode.GetByteCount(pin) + 2];
                        Encoding.Unicode.GetBytes(pin, 0, pin.Length, propertyBytes, 0);
                    }

                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    CngProperty pinProperty = new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None);

                    rsaCng.Key.SetProperty(pinProperty);
                    return rsaCng.Decrypt(encryptedMessage, padding);
                }
                throw new CryptographicException("The key is not compatible with Cryptography Next Generation (CNG)");
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value.
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <returns>Return signed hash as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] SignData(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm)
        {
            try
            {
                RSAParameters Params = privateKey.GetRSAPrivateKey().ExportParameters(true);
                if (privateKey.HasPrivateKey)
                {
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(Params);
                        byte[] signedBytes = rsa.SignData(data, CryptoConfig.MapNameToOID(hashAlgorithm.Name));
                        return signedBytes;
                    }
                }
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            return null;
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value using a certificate with a pin.
        /// https://stackoverflow.com/questions/42626742/how-can-i-set-pin-for-a-x509certificate2-programmatically
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return signed hash as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static byte[] SignData(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            try
            {
                RSA rsa = privateKey.GetRSAPrivateKey();
                RSACng rsaCng = rsa as RSACng;
                if (rsaCng != null)
                {
                    // Set the PIN, an explicit null terminator is required to this Unicode/UCS-2 string.

                    byte[] propertyBytes;

                    if (pin[pin.Length - 1] == '\0')
                    {
                        propertyBytes = Encoding.Unicode.GetBytes(pin);
                    }
                    else
                    {
                        propertyBytes = new byte[Encoding.Unicode.GetByteCount(pin) + 2];
                        Encoding.Unicode.GetBytes(pin, 0, pin.Length, propertyBytes, 0);
                    }

                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    CngProperty pinProperty = new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None);

                    rsaCng.Key.SetProperty(pinProperty);
                    return rsaCng.SignData(data, hashAlgorithm, padding);
                }
                throw new CryptographicException("The key is not compatible with Cryptography Next Generation (CNG)");
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key using a certificate with a pin.
        /// https://stackoverflow.com/questions/42626742/how-can-i-set-pin-for-a-x509certificate2-programmatically
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return signed hash as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static byte[] SignHash(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            try
            {
                RSA rsa = privateKey.GetRSAPrivateKey();
                RSACng rsaCng = rsa as RSACng;
                if (rsaCng != null)
                {
                    // Set the PIN, an explicit null terminator is required to this Unicode/UCS-2 string.
                    byte[] propertyBytes;

                    if (pin[pin.Length - 1] == '\0')
                    {
                        propertyBytes = Encoding.Unicode.GetBytes(pin);
                    }
                    else
                    {
                        propertyBytes = new byte[Encoding.Unicode.GetByteCount(pin) + 2];
                        Encoding.Unicode.GetBytes(pin, 0, pin.Length, propertyBytes, 0);
                    }

                    const string NCRYPT_PIN_PROPERTY = "SmartCardPin";

                    CngProperty pinProperty = new CngProperty(
                        NCRYPT_PIN_PROPERTY,
                        propertyBytes,
                        CngPropertyOptions.None);

                    rsaCng.Key.SetProperty(pinProperty);
                    return rsaCng.SignHash(hash, hashAlgorithm, padding);
                }
                throw new CryptographicException("The key is not compatible with Cryptography Next Generation (CNG)");
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key.
        /// </summary>
        /// <param name="hash">Hashed data to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The algorithm that will be used for signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <returns>Return signed hash as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] SignHash(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            try
            {
                RSAParameters Params = privateKey.GetRSAPrivateKey().ExportParameters(true);
                if (privateKey.HasPrivateKey)
                {
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(Params);
                        byte[] signedBytes = rsa.SignHash(hash, hashAlgorithm, padding);
                        return signedBytes;
                    }
                }
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
            return null;
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by hashing the data and then comparing it by decrypting the signature.
        /// </summary>
        /// <param name="data">Data (not hash) to be verified</param>
        /// <param name="signedData">The signed data</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyData(byte[] data, byte[] signedData, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm)
        {
            try
            {
                RSAParameters Params = publicKey.GetRSAPublicKey().ExportParameters(false);

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(Params);

                    return rsa.VerifyData(data, CryptoConfig.MapNameToOID(hashAlgorithm.Name), signedData);
                }
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by comparing the hashed data with the decrypted signature.
        /// </summary>
        /// <param name="hashedData">Hashed data to be verified</param>
        /// <param name="signedData">The signed data</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <param name="padding">The padding that was used in the signature</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyHash(byte[] hashedData, byte[] signedData, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            try
            {
                RSAParameters Params = publicKey.GetRSAPublicKey().ExportParameters(false);

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(Params);
                    return rsa.VerifyHash(hashedData, signedData, hashAlgorithm, padding);
                }
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }
    }
}
