## CryptoHelper
A library under MIT license made to help with cryptography operations such as RSA encryption and decryption, RSA signing and validation, and certificate generating with ease all what you need to do is add referance to CryptoHelper.dll and BouncyCastle.Crypto.dll in your project and please don't forget to include both [CryptoHelper](https://github.com/AlhasanDeveloper/CryptoHelper/blob/master/LICENSE) and [BouncyCastle](https://www.bouncycastle.org/license.html) license as well.

## The library include the following cryptography operations

* Accessing certificates on the connected smart card.
```cs
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
```

* Encryption and decryption using RSA certificates or CNG certificates with pin.
```cs
//Encrypt the message as a Base64 encoded string
string encryptedMessage = Crypto.Encrypt
(Encoding.UTF8.GetBytes(message), publicKeyExchange, RSAEncryptionPadding.OaepSHA1);
//Decrypt the Base64 encoded encrypted message
string decryptedMessage = Encoding.UTF8.GetString
(Crypto.Decrypt(encryptedMessage, privateKeyExchange, RSAEncryptionPadding.OaepSHA1));
```

* Signing and signature validation using RSA certificates or CNG certificates with pin.
```cs
//Sign the message into base64 string
string signedMessage = Crypto.SignData
(Encoding.UTF8.GetBytes(message), privateKeySignature, HashAlgorithmName.SHA512);
//Validate the signed message as base64 string
bool validationStatus = Crypto.VerifyData
(Encoding.UTF8.GetBytes(message), signedMessage, publicKeySignature, HashAlgorithmName.SHA512);
```

* Signing XML and XML signature validation using RSA certificates or CNG certificates with pin.
```cs
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
```

* Validating certificate using its parent through OCSP or CRL.
```cs
bool ocspValidationStatus = Crypto.ValidateCertificateWithOCSP(sampleCert, sampleCertIssuer);
bool crlValidationStatus = Crypto.ValidateCertificateWithCRL(sampleCert, sampleCertIssuer, true);
```

* Generating certificates and CSR.
```cs
X509Certificate2 cert = new X509Certificate2Builder
{
    DistinguishedName = new DistinguishedNames
    {
        commonName = "Selfsigned CA",
        countryName = "KW",
        localityName = "Hawally",
        organizationalUnitName = "My Organization Unit",
        organizationName = "My Organization"
    },
    SubjectAlternativeName = new SubjectAlternativeNames
    {
        Rfc822Name = "me@example.com"
    },
    friendlyName = "My CA",
    keyPurpose = new string[] { BuilderKeyPurpose.AnyExtendedKeyUsage },
    keyUsage = BuilderKeyUsage.DigitalSignature | BuilderKeyUsage.CrlSign | BuilderKeyUsage.KeyCertSign,
    signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
    NotAfter = DateTime.Now.AddYears(10)
}.Build();

X509Certificate2Builder.CSR csr = new X509Certificate2Builder
{
    DistinguishedName = new DistinguishedNames
    {
        commonName = "My CN",
        countryName = "KW",
        localityName = "Hawally",
        organizationalUnitName = "My Organization Unit",
        organizationName = "My Organization"
    },
    friendlyName = "My Friendly Name",
    keyPurpose = new string[] { },
    keyUsage = BuilderKeyUsage.DigitalSignature,
    signatureAlgorithm = PKCS15SignatureAlgorithm.SHA512WITHRSA,
    NotAfter = DateTime.Now.AddYears(10)
}.GenerateCSR();
X509Certificate2 csrPrivateKey = csr.PrivateKey;
string csrPEM = csr.CSRPEM;
```


## Release
To use CryptoHelper library please download the Library.zip at root and include both libraries to your project.

## Sample 
Please clone the project and run the samples for better understanding of the library.

## Future Plans
I plan to add PDF signing to CryptoHelper library in the near future.