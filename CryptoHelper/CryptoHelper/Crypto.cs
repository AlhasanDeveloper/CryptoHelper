using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace CryptoHelper
{
    public class Crypto
    {
        /// <summary>
        /// Holds CRL requests as cache
        /// </summary>
        private static Dictionary<string, CRLVerifier> crlDictionary = new Dictionary<string, CRLVerifier>();

        /// <summary>
        /// Validates the certificate using OCSP server
        /// </summary>
        /// <param name="eecert">End entity certificate to be validated</param>
        /// <param name="issuerCert">Issuer of the end entity certificate to be used in validating</param>
        /// <param name="proxy">Optional if a web proxy is required</param>
        /// <returns>Validation status of the end entity certificate</returns>
        /// <exception cref="OCSPExpection">Thrown when there is no OCSP URL in certificate or the OCSP URL in unreachable<exception>
        public static bool ValidateCertificateWithOCSP(X509Certificate2 eecert, X509Certificate2 issuerCert, WebProxy proxy = null)
        {
            Org.BouncyCastle.X509.X509Certificate bouncyeecert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(eecert);
            Org.BouncyCastle.X509.X509Certificate bouncyissuercert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(issuerCert);

            if (!bouncyeecert.IssuerDN.Equivalent(bouncyissuercert.SubjectDN))
                return false; //Not the same issuer.
            try
            {
                bouncyeecert.CheckValidity();
                bouncyeecert.Verify(bouncyissuercert.GetPublicKey());
                OCSPVerifier crypto = new OCSPVerifier();

                return (crypto.Query(bouncyeecert, bouncyissuercert, proxy) == OCSPVerifier.CertificateStatus.Good);
            }
            catch (OCSPExpection ocspe)
            {
                throw ocspe;//send to API user.
            }
            catch (WebException webx)
            {
                throw new OCSPExpection("Exception in accessing OCSP web server. Error: " + webx.Message);
            }
            catch (Exception)
            {
                //If any general exception is raised then there is a problem in validation, so return false.
                return false;
            }
        }

        /// <summary>
        /// Validates the certificate using CRL
        /// </summary>
        /// <param name="eeCert">End entity certificate to be validated</param>
        /// <param name="issuerCert">Issuer of the end entity certificate to be used in validating</param>
        /// <param name="online">CRL validation should be on-line or by using a file</param>
        /// <param name="CRLfilepath">Optional CRL file path required if the on-line parameters is false</param>
        /// <param name="proxy">Optional if a web proxy is required</param>
        /// <returns>Validation status of the end entity certificate</returns>
        /// <exception cref="CRLExpection">Thrown when there problem with the CRL</exception>
        public static bool ValidateCertificateWithCRL(X509Certificate2 eeCert, X509Certificate2 issuerCert, bool online, string CRLfilepath = null, WebProxy proxy = null)
        {
            Org.BouncyCastle.X509.X509Certificate bouncyeecert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(eeCert);
            Org.BouncyCastle.X509.X509Certificate bouncyissuercert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(issuerCert);

            if (!bouncyeecert.IssuerDN.Equivalent(bouncyissuercert.SubjectDN))
                return false; //Not the same issuer.
            try
            {
                bouncyeecert.CheckValidity();
                bouncyeecert.Verify(bouncyissuercert.GetPublicKey());
            }
            catch (Exception)
            {
                return false; /*The issuer public key does not match the signature in the certificate.*/
            }

            try
            {
                CRLVerifier crl = null;
                crlDictionary.TryGetValue(issuerCert.GetCertHashString(), out crl);
                if (crl == null)
                {
                    crl = new CRLVerifier(issuerCert);
                    crlDictionary.Add(issuerCert.GetCertHashString(), crl);
                }

                bool IsInCRL = false;
                if (online)
                    IsInCRL = crl.IsCertificateInOnlineCRL(eeCert, crl.GetBaseCrlUrl(eeCert), proxy);
                else
                {
                    IsInCRL = crl.IsCertificateInCrlFile(eeCert, CRLfilepath);
                }
                return !IsInCRL;
            }
            catch (CRLExpection crle)
            {
                throw crle;//send to API user.
            }
            catch (WebException webx)
            {
                throw new CRLExpection("Exception in accessing CRL web server. Error: " + webx.Message);
            }
            catch (IOException iox)
            {
                throw new CRLExpection("Exception in accessing CRL file. Error: " + iox.Message);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Encrypts the message using an exchange public key
        /// </summary>
        /// <param name="message">Message to be encrypted</param>
        /// <param name="publicKey">Public exchange key to encrypt the message</param>
        /// <param name="padding">Padding mode to be used with the encryption</param>
        /// <returns>Encrypted message as base64 string</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static string Encrypt(byte[] message, X509Certificate2 publicKey, RSAEncryptionPadding padding)
        {
            return Convert.ToBase64String(CertificateCrypto.Encrypt(message, publicKey, padding));
        }

        /// <summary>
        /// Encrypts the message using an exchange public key
        /// </summary>
        /// <param name="message">Message to be encrypted</param>
        /// <param name="publicKey">Public exchange key to encrypt the message</param>
        /// <param name="padding">Padding mode to be used with the encryption</param>
        /// <returns>Encrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] EncryptToByteArray(byte[] message, X509Certificate2 publicKey, RSAEncryptionPadding padding)
        {
            return CertificateCrypto.Encrypt(message, publicKey, padding);
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
            return CertificateCrypto.Decrypt(encryptedMessage, privateKey, padding);
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
            return CertificateCrypto.Decrypt(encryptedMessage, privateKey, padding, pin);
        }

        /// <summary>
        /// Decrypts the message using an exchange private key
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message as byte array</param>
        /// <param name="privateKey">Private exchange key to decrypt the message</param>
        /// <param name="padding">Padding mode to be used with the decryption</param>
        /// <returns>Decrypted message as byte array</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        /// <exception cref="FormatException">The length of string, ignoring white-space characters, is not zero or a multiple of 4. -or-The format of s is invalid. string contains a non-base-64 character, more than two padding characters, or a non-white space-character among the padding characters.</exception>
        public static byte[] Decrypt(byte[] encryptedMessage, X509Certificate2 privateKey, RSAEncryptionPadding padding)
        {
            return CertificateCrypto.Decrypt(encryptedMessage, privateKey, padding);
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
            return CertificateCrypto.Decrypt(encryptedMessage, privateKey, padding, pin);
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key.
        /// </summary>
        /// <param name="hash">Hashed data to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The algorithm that will be used for signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <returns>Return Base64 encoded sign string, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static string SignHash(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            return Convert.ToBase64String(CertificateCrypto.SignHash(hash, privateKey, hashAlgorithm, padding));
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key that has a pin.
        /// </summary>
        /// <param name="hash">Hashed data to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The algorithm that will be used for signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return Base64 encoded sign string, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static string SignHash(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            return Convert.ToBase64String(CertificateCrypto.SignHash(hash, privateKey, hashAlgorithm, padding, pin));
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
        public static byte[] SignHashByteArray(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            return CertificateCrypto.SignHash(hash, privateKey, hashAlgorithm, padding);
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key that has a pin.
        /// </summary>
        /// <param name="hash">Hashed data to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The algorithm that will be used for signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return signed hash as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static byte[] SignHashByteArray(byte[] hash, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            return CertificateCrypto.SignHash(hash, privateKey, hashAlgorithm, padding, pin);
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value.
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <returns>Return Base64 encoded sign string, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static string SignData(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm)
        {
            return Convert.ToBase64String(CertificateCrypto.SignData(data, privateKey, hashAlgorithm));
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value using a private key that uses pin.
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return Base64 encoded sign string, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static string SignData(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            return Convert.ToBase64String(CertificateCrypto.SignData(data, privateKey, hashAlgorithm, padding, pin));
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value.
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <returns>Return signed data as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid.</exception>
        public static byte[] SignDataByteArray(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm)
        {
            return CertificateCrypto.SignData(data, privateKey, hashAlgorithm);
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm,
        /// and signs the resulting hash value.
        /// </summary>
        /// <param name="data">Data (not hash) to be signed</param>
        /// <param name="privateKey">The private key used for signing</param>
        /// <param name="hashAlgorithm">The hash algorithm used in hashing the data before signing</param>
        /// <param name="padding">The padding that will be used in the signature</param>
        /// <param name="pin">The private key pin</param>
        /// <returns>Return signed data as byte array, or null if fails</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields. -or- The padding mode is not supported. -or- The certificate context is invalid. -or- wrong pin has been inputed.</exception>
        public static byte[] SignDataByteArray(byte[] data, X509Certificate2 privateKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, string pin)
        {
            return CertificateCrypto.SignData(data, privateKey, hashAlgorithm, padding, pin);
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by comparing the hashed data with the decrypted signature.
        /// </summary>
        /// <param name="hashedData">Hashed data to be verified</param>
        /// <param name="encodedsiged">The encoded hashed and signed data</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <param name="padding">The padding that was used in the signature</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyHash(byte[] data, string encodedSigned, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            byte[] signedHash = Convert.FromBase64String(encodedSigned);
            return CertificateCrypto.VerifyHash(data, signedHash, publicKey, hashAlgorithm, padding);
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by comparing the hashed data with the decrypted signature.
        /// </summary>
        /// <param name="hashedData">Hashed data to be verified</param>
        /// <param name="signedHash">Signed hash as byte array</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <param name="padding">The padding that was used in the signature</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyHash(byte[] data, byte[] signedHash, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            return CertificateCrypto.VerifyHash(data, signedHash, publicKey, hashAlgorithm, padding);
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by hashing the data and then comparing it by decrypting the signature.
        /// </summary>
        /// <param name="data">Data (not hash) to be verified</param>
        /// <param name="encodedsiged">The encoded hashed and signed data</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyData(byte[] data, string encodedSigned, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm)
        {
            byte[] signedData = Convert.FromBase64String(encodedSigned);
            return CertificateCrypto.VerifyData(data, signedData, publicKey, hashAlgorithm);
        }

        /// <summary>
        /// Verifies that the base64 encoded signature is valid by hashing the data and then comparing it by decrypting the signature.
        /// </summary>
        /// <param name="data">Data (not hash) to be verified</param>
        /// <param name="signedData">The signed data as byte array</param>
        /// <param name="publicKey">Public key that is the RSA pair of the private key that signed the message</param>
        /// <param name="hashAlgorithm">The algorithm used for signing</param>
        /// <returns>Return true if data is Verified</returns>
        /// <exception cref="ArgumentException">There is null in the parameters or one of the parameters empty</exception>
        /// <exception cref="CryptographicException">The cryptographic service provider (CSP) cannot be acquired.-or- The parameters parameter has missing fields.</exception>
        public static bool VerifyData(byte[] data, byte[] signedData, X509Certificate2 publicKey, HashAlgorithmName hashAlgorithm)
        {
            return CertificateCrypto.VerifyData(data, signedData, publicKey, hashAlgorithm);
        }

        /// <summary>
        /// Hash data using the provided hash algorithm
        /// </summary>
        /// <param name="data">The data to be hashed</param>
        /// <param name="hashAlgorithm">The hash algorithm that will be used for hashing</param>
        /// <returns>Base64 string of hashed data</returns>
        /// <exception cref="ArgumentNullException">data is null. -or- hashAlgorithm invalid</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public static string HashData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            HashAlgorithm ha = HashAlgorithm.Create(hashAlgorithm.Name);
            if (ha == null)
            {
                throw new ArgumentNullException("hashAlgorithm invalid");
            }
            byte[] hashedData = ha.ComputeHash(data);
            return Convert.ToBase64String(hashedData);
        }

        /// <summary>
        /// Hash data using the provided hash algorithm
        /// </summary>
        /// <param name="data">The data to be hashed</param>
        /// <param name="hashAlgorithm">The hash algorithm that will be used for hashing</param>
        /// <returns>Base64 string of hashed data</returns>
        /// <exception cref="ArgumentNullException">data is null. -or- hashAlgorithm invalid</exception>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="EncoderFallbackException">Data is not UTF-8 encoded.</exception>
        public static string HashData(string data, HashAlgorithmName hashAlgorithm)
        {
            HashAlgorithm ha = HashAlgorithm.Create(hashAlgorithm.Name);
            if (ha == null)
            {
                throw new ArgumentNullException("hashAlgorithm not valid");
            }

            byte[] DataToHash = Encoding.UTF8.GetBytes(data);

            byte[] hashedData = ha.ComputeHash(DataToHash);
            return Convert.ToBase64String(hashedData);
        }

        /// <summary>
        /// Sign XML data.
        /// </summary>
        /// <param name="xmlData">XML object as a string which will be signed.</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document.</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not (only RSA keys supported).</param>
        /// <returns>Signed XML string object.</returns>
        /// <exception cref="XmlException">There is a load or parse error in the XML.</exception>
        /// <exception cref="ArgumentNullException">Private key is null or any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.</exception>
        /// <exception cref="NotSupportedException">The key algorithm for this private key is not supported.</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">The X.509 keys do not match.</exception>
        /// <exception cref="ArgumentException">The cryptographic service provider key is null.</exception>
        public static string SignXml(string xmlData, X509Certificate2 signingKey, bool addKey)
        {
            return XMLSigning.SignXml(xmlData, signingKey, addKey);
        }

        /// <summary>
        /// Sign XML data.
        /// </summary>
        /// <param name="xmlData">XML object as a string which will be signed.</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document.</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not (only RSA keys supported).</param>
        /// <param name="pin">The pin of the CNG certificate.</param>
        /// <returns>Signed XML string object.</returns>
        /// <exception cref="XmlException">There is a load or parse error in the XML.</exception>
        /// <exception cref="ArgumentNullException">Private key is null or any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.</exception>
        /// <exception cref="NotSupportedException">The key algorithm for this private key is not supported.</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">The X.509 keys do not match.</exception>
        /// <exception cref="ArgumentException">The cryptographic service provider key is null.</exception>
        public static string SignXml(string xmlData, X509Certificate2 signingKey, bool addKey, string pin)
        {
            return XMLSigning.SignXml(xmlData, signingKey, addKey, pin);
        }

        /// <summary>
        /// Verify the signature of an XML string against an asymmetric algorithm and return the result.
        /// </summary>
        /// <param name="xmlData">XML string which holds the signed XML data.</param>
        /// <param name="signingKey">RSA public key that is associated with the key that was used in signing the XML.</param>
        /// <returns>The status of the verification.</returns>
        /// <exception cref="NotSupportedException">The key algorithm is not supported.</exception>
        /// <exception cref="XmlException">There is a load or parse error in the XML.</exception>
        /// <exception cref="ArgumentNullException">Any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.
        /// -OR- No signature found or more than one signature found. 
        /// -OR- The value parameter does not contain a valid signature or signature info. 
        /// -OR- The signature algorithm of the key parameter does not match the signature method. 
        /// -OR- The signature description could not be created. 
        /// -OR- The hash algorithm could not be created.</exception>
        public static bool VerifyXml(string xmlData, X509Certificate2 signingKey)
        {
            return XMLSigning.VerifyXml(xmlData, signingKey);
        }

        /// <summary>
        /// Verify the signature of an XML string that contains key info against an asymmetric algorithm and return the result.
        /// </summary>
        /// <param name="xmlData">XML document as a string which holds the signed XML data with key info tag.</param>
        /// <returns>The status of the verification.</returns>
        /// <exception cref="XmlException">There is a load or parse error in the XML.</exception>
        /// <exception cref="CryptographicException">No signature found or more than one signature found. 
        /// -OR- The value parameter does not contain a valid signature or signature info. 
        /// -OR- The signature algorithm of the key parameter does not match the signature method. 
        /// -OR- The signature description could not be created. 
        /// -OR- The hash algorithm could not be created.</exception>
        public static bool VerifyXml(string xmlData)
        {
            return XMLSigning.VerifyXml(xmlData);
        }
    }
}
