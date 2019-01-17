using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace CryptoHelper
{
    /// <summary>
    /// Class for the handling of XML signature.
    /// </summary>
    internal class XMLSigning
    {
        /// <summary>
        /// Sign XML data.
        /// </summary>
        /// <param name="xmlData">XML object as a string which will be signed.</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document (only RSA keys supported).</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not.</param>
        /// <returns>Signed XML string object.</returns>
        /// <exception cref="XmlException">There is a load or parse error in the XML.</exception>
        /// <exception cref="ArgumentNullException">Private key is null or any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.</exception>
        /// <exception cref="NotSupportedException">The key algorithm for this private key is not supported.</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">The X.509 keys do not match.</exception>
        /// <exception cref="ArgumentException">The cryptographic service provider key is null.</exception>
        public static string SignXml(string xmlData, X509Certificate2 signingKey, bool addKey)
        {
            // Create a new XML document.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML data into the XmlDocument object.
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(xmlData);

            // Sign the XML document. 
            SignXml(xmlDoc, signingKey, addKey);

            //return the updated XML as string
            using (var stringWriter = new StringWriter())
            using (var xmlTextWriter = XmlWriter.Create(stringWriter))
            {
                xmlDoc.WriteTo(xmlTextWriter);
                xmlTextWriter.Flush();
                return stringWriter.GetStringBuilder().ToString();
            }
        }

        /// <summary>
        /// Sign XML data.
        /// </summary>
        /// <param name="xmlData">XML object as a string which will be signed.</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document (only RSA keys supported).</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not.</param>
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
            // Create a new XML document.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML data into the XmlDocument object.
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(xmlData);

            // Sign the XML document. 
            SignXml(xmlDoc, signingKey, addKey, pin);

            //return the updated XML as string
            using (var stringWriter = new StringWriter())
            using (var xmlTextWriter = XmlWriter.Create(stringWriter))
            {
                xmlDoc.WriteTo(xmlTextWriter);
                xmlTextWriter.Flush();
                return stringWriter.GetStringBuilder().ToString();
            }
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
            // Create RSA signing key and save it in the container. 
            RSACryptoServiceProvider rsaKey = signingKey.PublicKey.Key as RSACryptoServiceProvider;

            // Create a new XML document.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML data into the XmlDocument object.
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(xmlData);

            // Sign the XML document. 
            return VerifyXml(xmlDoc, rsaKey);
        }

        /// <summary>
        /// Sign an XML file.
        /// </summary>
        /// <param name="xmlDoc"> XML document object that holds the XML data</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not</param>
        /// <exception cref="ArgumentNullException">Private key is null or any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.</exception>
        /// <exception cref="NotSupportedException">The key algorithm for this private key is not supported.</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">The X.509 keys do not match.</exception>
        /// <exception cref="ArgumentException">The cryptographic service provider key is null.</exception>
        private static void SignXml(XmlDocument xmlDoc, X509Certificate2 signingKey, bool addKey)
        {
            if (signingKey == null)
                throw new ArgumentNullException("signingKey is null");

            // Create RSA signing key and save it in the container. 
            RSACryptoServiceProvider key = signingKey.PrivateKey as RSACryptoServiceProvider;

            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentNullException("xmlDoc is null");
            if (key == null)
                throw new ArgumentNullException("Private key is null");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = key;

            // Add public key of the certificate
            if (addKey)
            {
                KeyInfo keyInfo = new KeyInfo();
                KeyInfoX509Data keyInfoData = new KeyInfoX509Data(signingKey);
                keyInfo.AddClause(keyInfoData);
                signedXml.KeyInfo = keyInfo;
            }

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        /// <summary>
        /// Sign an XML file.
        /// </summary>
        /// <param name="xmlDoc"> XML document object that holds the XML data</param>
        /// <param name="signingKey">The certificate which will be used in signing the XML document</param>
        /// <param name="addKey">Flag to indicate if the public key should be included in the signed XML document or not</param>
        /// <param name="pin">The pin of the CNG certificate.</param>
        /// <exception cref="ArgumentNullException">Private key is null or any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">The key value is not an RSA key, or the key is unreadable.</exception>
        /// <exception cref="NotSupportedException">The key algorithm for this private key is not supported.</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">The X.509 keys do not match.</exception>
        /// <exception cref="ArgumentException">The cryptographic service provider key is null.</exception>
        private static void SignXml(XmlDocument xmlDoc, X509Certificate2 signingKey, bool addKey, string pin)
        {
            if (signingKey == null)
                throw new ArgumentNullException("signingKey is null");

            // Create RSA signing key and save it in the container. 
            RSACng key = null;

            // Try to load the RSA CNG key into key container.
            try
            {
                RSA rsa = signingKey.GetRSAPrivateKey();
                key = rsa as RSACng;
                if (key != null)
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

                    key.Key.SetProperty(pinProperty);
                }
                else
                {
                    throw new CryptographicException("The key is not compatible with Cryptography Next Generation (CNG)");
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

            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentNullException("xmlDoc is null");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc)
            {
                // Add the key to the SignedXml document.
                SigningKey = key ?? throw new ArgumentNullException("Private key is null")
            };

            // Add public key of the certificate
            if (addKey)
            {
                KeyInfo keyInfo = new KeyInfo();
                KeyInfoX509Data keyInfoData = new KeyInfoX509Data(signingKey);
                keyInfo.AddClause(keyInfoData);
                signedXml.KeyInfo = keyInfo;
            }

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }


        //TODO UPDATE SIGNATURE VERIFICATION TO ALLOW MORE THAN ONE SIGNATURE
        /// <summary>
        /// Verify the signature of an XML object against an asymmetric algorithm and return the result.
        /// </summary>
        /// <param name="Doc">XML document object which holds the signed XML data.</param>
        /// <param name="Key">The RSA public key which signed the XML.</param>
        /// <returns>The status of the verification.</returns>
        /// <exception cref="ArgumentNullException">Any of the passed arguments is null.</exception>
        /// <exception cref="CryptographicException">No signature found or more than one signature found. 
        /// -OR- The value parameter does not contain a valid signature or signature info. 
        /// -OR- The signature algorithm of the key parameter does not match the signature method. 
        /// -OR- The signature description could not be created. 
        /// -OR- The hash algorithm could not be created.</exception>
        private static bool VerifyXml(XmlDocument Doc, RSA Key)
        {
            // Check arguments.
            if (Doc == null)
                throw new ArgumentException("Doc");
            if (Key == null)
                throw new ArgumentException("Key");

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(Doc);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = Doc.GetElementsByTagName("Signature");

            // Throw an exception if no signature was found.
            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }

            // This example only supports one signature for
            // the entire XML document.  Throw an exception 
            // if more than one signature was found.
            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");
            }

            // Load the first <signature> node.  
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature(Key);
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
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Format using white spaces.
            xmlDocument.PreserveWhitespace = true;

            // Load the passed XML file into the document. 
            xmlDocument.LoadXml(xmlData);

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Throw an exception if no signature was found.
            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }

            // This example only supports one signature for
            // the entire XML document.  Throw an exception 
            // if more than one signature was found.
            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");
            }

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature();
        }
        //END TODO
    }
}
