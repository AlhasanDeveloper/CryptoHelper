using CryptoHelper;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CreateCertSignedFromStore_Sample
{
    /// <summary>
    /// This a sample program on how to use an existing CA to create a certificate from it 
    /// please note that in case of computer store the run should be in administrator mode.
    /// </summary>
    internal class Program
    {
        private static void Main(string[] args)
        {
            //Take the thumb print from user
            Console.Write("Please input the CA thumb print: ");
            string caThumbprint = Console.ReadLine();
            Console.WriteLine("Finding CA from store...");

            //Search the store for it
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindByThumbprint, caThumbprint, false);
            store.Close();

            //See if cert was found
            if (cers.Count <= 0)
            {
                Console.WriteLine("No certificate was found.");
            }
            //Cert was found now check for if you have its private key
            else if (cers[0].HasPrivateKey)
            {
                //Now we have the certificate and it has a private key no check if the certificate is capable of signing another certificate.
                bool hasKeyCertSign = false;
                foreach (X509Extension extension in cers[0].Extensions)
                {
                    //OID 2.5.29.15 is for key usage
                    if (extension.Oid.Value.Equals("2.5.29.15"))
                    {
                        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                        //the key usage KeyCertSign is used for signing certificates
                        if ((ext.KeyUsages & X509KeyUsageFlags.KeyCertSign) == X509KeyUsageFlags.KeyCertSign)
                        {
                            hasKeyCertSign = true;
                        }
                    }
                }

                //Check if the certificate had KeyCertSign as key usage
                if (hasKeyCertSign)
                {
                    X509Certificate2 ca = cers[0];

                    //Initialize the new certificate
                    X509Certificate2Builder cerBuilder = new X509Certificate2Builder
                    {
                        DistinguishedName = new DistinguishedNames
                        {
                            commonName = "www.example.com",
                            organizationName = "Example Organization",
                            organizationalUnitName = "Example Organization Unit",
                            localityName = "Hawally",
                            stateOrProvinceName = "Kuwait",
                            countryName = "KW"
                        },
                        SubjectAlternativeName = new SubjectAlternativeNames
                        {
                            Rfc822Name = "me@example.com",
                            DnsName = new string[]
                            {
                                "www.example.com",
                                "example.com",
                                "api.example.com",
                                "ws.example.com",
                                "admin.example.com",
                                "you.example.com",
                            }
                        },
                        friendlyName = "My Server Certificate",
                        Issuer = ca,
                        Intermediate = false,
                        keyPurpose = new string[]
                        {
                            BuilderKeyPurpose.IdKPClientAuth,
                            BuilderKeyPurpose.IdKPServerAuth
                        },
                        keyUsage = BuilderKeyUsage.DigitalSignature | BuilderKeyUsage.KeyEncipherment,
                        signatureAlgorithm = PKCS15SignatureAlgorithm.SHA256WITHRSA,
                        NotAfter = DateTime.Now.AddYears(3)
                    };

                    //Build the certificate
                    Console.WriteLine("Building the certificate...");
                    X509Certificate2 ee = cerBuilder.Build();
                    Console.WriteLine("Done building, now exporting the private key.");

                    //Export the private key as PFX
                    Byte[] certData = ee.Export(X509ContentType.Pkcs12, "abc123");
                    File.WriteAllBytes("EE.pfx", certData);

                    Console.WriteLine("Done, please find the file EE.pfx at the run location.");
                }
                else
                {
                    Console.WriteLine("The certificate found is not a CA.");
                }
            }
            else
            {
                Console.WriteLine("The certificate has no private key or .");
            }
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}