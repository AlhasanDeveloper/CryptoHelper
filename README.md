# CryptoHelper
A library made to help with Cryptography operations with ease.

## The library include the following cryptography operations:

* Accessing certificates on the connected smart card.
* Encryption and decryption using RSA certificates or CNG certificates with pin.
```cs
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
```
* Signing and signature validation using RSA certificates or CNG certificates with pin.
* Signing XML and XML signature validation using RSA certificates or CNG certificates with pin.
* Validating certificate using its parent through OCSP or CRL.
* Generating certificates and CSR.

## Release
To use CryptoHelper library please download the Library.zip at root and include both libraries to your project.

## Sample 
Please clone the project and run the samples for better understanding of the library.
