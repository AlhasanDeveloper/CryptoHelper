using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace CryptoHelper
{
    /// <summary>
    /// Class used for OCSP verifications
    /// </summary>
    internal class OCSPVerifier
    {
        public static readonly int BufferSize = 4096 * 8;
        private readonly int MaxClockSkew = 36000000;
        private readonly string OCSPSigning = "1.3.6.1.5.5.7.3.9";//OID for OCSP Signing. A certificate from the same issuer must
        private static readonly string OCSP_OID = "1.3.6.1.5.5.7.48.1";//OID for OCSP

        //have this OID in its usage to be allowed to sign OCSP Responses.

        public enum CertificateStatus { Good, Revoked, Unknown };

        // This function makes a post request to the OCSP server and returns the response. A proxy can be used optionally.
        public static byte[] PostData(string url, byte[] data, string contentType, string accept, WebProxy proxy = null)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            if (proxy != null)
                request.Proxy = proxy;
            request.Method = "POST";
            request.ContentType = contentType;
            request.ContentLength = data.Length;
            request.Accept = accept;
            Stream stream = request.GetRequestStream();
            stream.Write(data, 0, data.Length);
            stream.Close();
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream respStream = response.GetResponseStream();
            byte[] resp = ToByteArray(respStream);
            respStream.Close();

            return resp;
        }

        public static byte[] ToByteArray(Stream stream)
        {
            byte[] buffer = new byte[BufferSize];
            MemoryStream ms = new MemoryStream();

            int read = 0;

            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }

            return ms.ToArray();
        }

        //Get OCSP URLs from a certificate by checking the extensions, finding the OCSP extension and extracting its URLs.
        public static List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
        {
            List<string> ocspUrls = new List<string>();

            try
            {
                Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }

                Asn1Sequence s = (Asn1Sequence)obj;
                IEnumerator elements = s.GetEnumerator();

                while (elements.MoveNext())
                {
                    Asn1Sequence element = (Asn1Sequence)elements.Current;
                    DerObjectIdentifier oid = (DerObjectIdentifier)element[0];

                    if (oid.Id.Equals(OCSP_OID)) // Is OID == OCSP?
                    {
                        Asn1TaggedObject taggedObject = (Asn1TaggedObject)element[1];
                        GeneralName gn = (GeneralName)GeneralName.GetInstance(taggedObject);
                        ocspUrls.Add(((DerIA5String)DerIA5String.GetInstance(gn.Name)).GetString());
                    }
                }
            }
            catch (Exception e)
            {
                throw new OCSPExpection("Error parsing AIA.", e);
            }

            return ocspUrls;
        }

        // Find the value of an extension inside a given certificate for a given OID.
        protected static Asn1Object GetExtensionValue(X509Certificate cert,
        string oid)
        {
            if (cert == null)
            {
                return null;
            }

            byte[] bytes = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            Asn1InputStream aIn = new Asn1InputStream(bytes);

            return aIn.ReadObject();
        }

        // Query the OCSP server and return the certificate status. A proxy can be optionally used.
        public CertificateStatus Query(X509Certificate eeCert, X509Certificate issuerCert, WebProxy proxy = null)
        {
            // Query the first OCSP URL found in certificate
            List<string> urls = GetAuthorityInformationAccessOcspUrl(eeCert);

            if (urls.Count == 0)
            {
                throw new OCSPExpection("No OCSP URL found in EE certificate.");
            }

            string url = urls[0];

            OcspReq req = GenerateOcspRequest(issuerCert, eeCert.SerialNumber);

            byte[] binaryResp = PostData(url, req.GetEncoded(), "application/ocsp-request", "application/ocsp-response", proxy);

            return ProcessOcspResponse(eeCert, issuerCert, binaryResp);
        }

        private CertificateStatus ProcessOcspResponse(X509Certificate eeCert, X509Certificate issuerCert, byte[] binaryResp)
        {
            OcspResp r = new OcspResp(binaryResp);
            CertificateStatus cStatus = CertificateStatus.Unknown;

            switch (r.Status)
            {
                case OcspRespStatus.Successful:
                    BasicOcspResp or = (BasicOcspResp)r.GetResponseObject();

                    ValidateResponse(or, issuerCert);

                    if (or.Responses.Length == 1)
                    {
                        SingleResp resp = or.Responses[0];

                        ValidateCertificateId(issuerCert, eeCert, resp.GetCertID());
                        ValidateThisUpdate(resp);
                        ValidateNextUpdate(resp);

                        Object certificateStatus = resp.GetCertStatus();

                        if (certificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            cStatus = CertificateStatus.Good;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            cStatus = CertificateStatus.Revoked;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            cStatus = CertificateStatus.Unknown;
                        }
                    }
                    break;

                default:
                    throw new OCSPExpection("Unknown status '" + r.Status + "'.");
            }

            return cStatus;
        }

        private void ValidateResponse(BasicOcspResp or, X509Certificate issuerCert)
        {
            X509Certificate OCSPRespondercert = or.GetCerts()[0];

            ValidateSignerAuthorization(issuerCert, OCSPRespondercert);
            ValidateResponseSignature(or, OCSPRespondercert.GetPublicKey());
        }

        //3. The identity of the signer matches the intended recipient of the
        //request.
        //4. The signer is currently authorized to sign the response.
        private void ValidateSignerAuthorization(X509Certificate issuerCert, X509Certificate signerCert)
        {
            // This code just check if the signer certificate is the same that issued the EE certificate
            // See RFC 2560 for more information
            // Check if the issuer is not the same as the signer. If they are then return because the issuer is by default allowed to be an OCSP signer.
            if (!issuerCert.SerialNumber.Equals(signerCert.SerialNumber))
            {
                if (issuerCert.SubjectDN.Equivalent(signerCert.IssuerDN))
                {
                    if (signerCert.GetExtendedKeyUsage().Contains(OCSPSigning)) //If OCSP Responder is authorized to produce OCSP responses.
                    {
                        return;
                    }

                    throw new OCSPExpection("Signer does not have OCSP signing OID " + OCSPSigning + " in Extended Key Usage");
                }
                throw new OCSPExpection("Invalid OCSP signer");
            }
        }

        //2. The signature on the response is valid;
        private void ValidateResponseSignature(BasicOcspResp or, Org.BouncyCastle.Crypto.AsymmetricKeyParameter asymmetricKeyParameter)
        {
            if (!or.Verify(asymmetricKeyParameter))
            {
                throw new OCSPExpection("Invalid OCSP signature");
            }
        }

        //6. When available, the time at or before which newer information will
        //be available about the status of the certificate (nextUpdate) is
        //greater than the current time.
        private void ValidateNextUpdate(SingleResp resp)
        {
            if (resp.NextUpdate != null && resp.NextUpdate.Value != null && resp.NextUpdate.Value.Ticks <= DateTime.Now.Ticks)
            {
                //NEWthrow new Exception("Invalid next update.");
            }
        }

        //5. The time at which the status being indicated is known to be
        //correct (thisUpdate) is sufficiently recent.
        private void ValidateThisUpdate(SingleResp resp)
        {
            if (Math.Abs(resp.ThisUpdate.Ticks - DateTime.Now.Ticks) > MaxClockSkew)
            {
                //NEWthrow new Exception("Max clock skew reached.");
            }
        }

        //1. The certificate identified in a received response corresponds to
        //that which was identified in the corresponding request;
        private void ValidateCertificateId(X509Certificate issuerCert, X509Certificate eeCert, CertificateID certificateId)
        {
            CertificateID expectedId = new CertificateID(CertificateID.HashSha1, issuerCert, eeCert.SerialNumber);

            if (!expectedId.SerialNumber.Equals(certificateId.SerialNumber))
            {
                throw new OCSPExpection("Invalid certificate ID in response");
            }

            if (!Org.BouncyCastle.Utilities.Arrays.AreEqual(expectedId.GetIssuerNameHash(), certificateId.GetIssuerNameHash()))
            {
                throw new OCSPExpection("Invalid certificate Issuer in response");
            }
        }

        private OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
        {
            CertificateID id = new CertificateID(CertificateID.HashSha1, issuerCert, serialNumber);
            return GenerateOcspRequest(id);
        }

        private OcspReq GenerateOcspRequest(CertificateID id)
        {
            OcspReqGenerator ocspRequestGenerator = new OcspReqGenerator();

            ocspRequestGenerator.AddRequest(id);

            BigInteger nonce = BigInteger.ValueOf(new DateTime().Ticks);

            ArrayList oids = new ArrayList();
            Hashtable values = new Hashtable();

            oids.Add(OcspObjectIdentifiers.PkixOcsp);

            Asn1OctetString asn1 = new DerOctetString(new DerOctetString(new byte[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 }));//1.3.6.1.5.5.7.48.1.1 - Basic OCSP Response OID

            values.Add(OcspObjectIdentifiers.PkixOcsp, new X509Extension(false, asn1));
            ocspRequestGenerator.SetRequestExtensions(new X509Extensions(oids, values));

            return ocspRequestGenerator.Generate();
        }
    }
}
