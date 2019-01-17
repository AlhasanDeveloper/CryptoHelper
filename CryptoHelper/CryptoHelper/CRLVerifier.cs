using System;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace CryptoHelper
{
    /// <summary>
    /// Class used for CRL verifications.
    /// </summary>
    internal class CRLVerifier
    {
        private DateTime CRLNextUpdate; //Validity of each CRL.
        private DateTime CRLDownloadedExpiry;// One-hour freshness of each CRL. Download a new CRL if 1 hour passed since last download.
        private byte[] CRLData;
        private const string CRL_DISTRIBUTION_POINT_OID = "2.5.29.31";
        private const string CRL_FRESH_DELTA_OID = "2.5.29.46";

        // #define X509_ASN_ENCODING           0x00000001
        public const Int32 X509_ASN_ENCODING = 0x00000001;

        // #define PKCS_7_ASN_ENCODING         0x00010000
        public const Int32 PKCS_7_ASN_ENCODING = 0x00010000;

        private X509Certificate2 IssuerCertificate = null;

        internal CRLVerifier(X509Certificate2 issuer)
        {
            IssuerCertificate = issuer;
        }

        /// <summary>
        /// Get CRL URL from Certificate
        /// </summary>
        /// <param name="cert"> Certificate</param>
        /// <returns>string of CRL URL</returns>
        internal string GetBaseCrlUrl(X509Certificate2 cert)
        {
            try
            {
                foreach (X509Extension extension in cert.Extensions)
                {
                    if (extension.Oid.Value.Equals(CRL_DISTRIBUTION_POINT_OID))// Find CRL extension by the CRL OID.
                    {
                        return GetCrlUrlFromExtension(extension); // Get the CRL URL.
                    }
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// In case of delta CRL this function will return the delta CRL location.
        /// </summary>
        /// <param name="stCrlInfo"> win32 CRL INFO</param>
        /// <returns>URL for CRL</returns>
        private string GetDeltaCrlUrl(WinCrypt32.CRL_INFO stCrlInfo)
        {
            IntPtr rgExtension = stCrlInfo.rgExtension;
            X509Extension deltaCrlExtension = null;

            for (int i = 0; i < stCrlInfo.cExtension; i++)
            {
                WinCrypt32.CERT_EXTENSION stCrlExt = (WinCrypt32.CERT_EXTENSION)Marshal.PtrToStructure(rgExtension, typeof(WinCrypt32.CERT_EXTENSION));

                if (stCrlExt.Value.pbData != IntPtr.Zero && stCrlExt.pszObjId == CRL_FRESH_DELTA_OID)
                {
                    byte[] rawData = new byte[stCrlExt.Value.cbData];
                    Marshal.Copy(stCrlExt.Value.pbData, rawData, 0, rawData.Length);
                    deltaCrlExtension = new X509Extension(stCrlExt.pszObjId, rawData, stCrlExt.fCritical);
                    break;
                }

                rgExtension = (IntPtr)((Int32)rgExtension + Marshal.SizeOf(typeof(WinCrypt32.CERT_EXTENSION)));
            }
            if (deltaCrlExtension == null)
            {
                return null;
            }
            return GetCrlUrlFromExtension(deltaCrlExtension);
        }

        /// <summary>
        /// Gets the CRL from the extension assuming that the CRL will always end with .crl extension.
        /// </summary>
        /// <param name="extension">Extension that may have the CRL</param>
        /// <returns>URL for CRL</returns>
        private string GetCrlUrlFromExtension(X509Extension extension)
        {
            try
            {
                Regex rx = new Regex("http://.*crl");
                string raw = new AsnEncodedData(extension.Oid, extension.RawData).Format(false);
                return rx.Match(raw).Value;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Checks if the Certificate is in the specific CRL list
        /// </summary>
        /// <param name="cert">Certificate</param>
        /// <param name="stCrlInfo">CRL structure ASN.1</param>
        /// <returns>true in case of certificate is in the revocation list</returns>
        private bool IsCertificateInCrl(X509Certificate2 cert, WinCrypt32.CRL_INFO stCrlInfo)
        {
            IntPtr rgCrlEntry = stCrlInfo.rgCRLEntry;

            for (int i = 0; i < stCrlInfo.cCRLEntry; i++)
            {
                string serial = string.Empty;
                WinCrypt32.CRL_ENTRY stCrlEntry = (WinCrypt32.CRL_ENTRY)Marshal.PtrToStructure(rgCrlEntry, typeof(WinCrypt32.CRL_ENTRY));

                IntPtr pByte = stCrlEntry.SerialNumber.pbData;
                for (int j = 0; j < stCrlEntry.SerialNumber.cbData; j++)
                {
                    Byte bByte = Marshal.ReadByte(pByte);
                    serial = bByte.ToString("X").PadLeft(2, '0') + serial;
                    pByte = (IntPtr)((Int32)pByte + Marshal.SizeOf(typeof(Byte)));
                }
                if (cert.SerialNumber == serial)
                {
                    return true;
                }
                rgCrlEntry = (IntPtr)((Int32)rgCrlEntry + Marshal.SizeOf(typeof(WinCrypt32.CRL_ENTRY)));
            }
            return false;
        }

        /// <summary>
        /// can be used to check if the certificate is available in a specific URL for CRL. A proxy can be optionally used.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="url"></param>
        /// <param name="proxy"></param>
        /// <returns></returns>
        internal bool IsCertificateInOnlineCRL(X509Certificate2 cert, string url, WebProxy proxy = null)
        {
            if (CRLNextUpdate < DateTime.Now /* is CRLNextupdate expired*/ || CRLDownloadedExpiry < DateTime.Now /*is Downloaded CRL expired*/)//check if locally cached CRL is still valid.
            {
                WebClient wc = new WebClient();
                if (proxy != null)
                    wc.Proxy = proxy;
                CRLData = wc.DownloadData(url);
                CRLDownloadedExpiry = DateTime.Now.AddHours(1);
            }

            if (!CheckCRLMessageSignature(CRLData)) return false;

            IntPtr phCertStore = IntPtr.Zero;
            IntPtr pvContext = IntPtr.Zero;
            GCHandle hCrlData = new GCHandle();
            GCHandle hCryptBlob = new GCHandle();
            try
            {
                hCrlData = GCHandle.Alloc(CRLData, GCHandleType.Pinned);
                WinCrypt32.CRYPTOAPI_BLOB stCryptBlob;
                stCryptBlob.cbData = CRLData.Length;
                stCryptBlob.pbData = hCrlData.AddrOfPinnedObject();
                hCryptBlob = GCHandle.Alloc(stCryptBlob, GCHandleType.Pinned);

                if (!WinCrypt32.CryptQueryObject(
                WinCrypt32.CERT_QUERY_OBJECT_BLOB,
                hCryptBlob.AddrOfPinnedObject(),
                WinCrypt32.CERT_QUERY_CONTENT_FLAG_CRL,
                WinCrypt32.CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref phCertStore,
                IntPtr.Zero,
                ref pvContext
                ))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                WinCrypt32.CRL_CONTEXT stCrlContext = (WinCrypt32.CRL_CONTEXT)Marshal.PtrToStructure(pvContext, typeof(WinCrypt32.CRL_CONTEXT));
                WinCrypt32.CRL_INFO stCrlInfo = (WinCrypt32.CRL_INFO)Marshal.PtrToStructure(stCrlContext.pCrlInfo, typeof(WinCrypt32.CRL_INFO));

                CRLNextUpdate = WinCrypt32.FiletimeToDateTime(stCrlInfo.NextUpdate);

                if (CRLNextUpdate < DateTime.Now)
                {
                    throw new CRLExpection("CRL has expired");
                }

                if (IsCertificateInCrl(cert, stCrlInfo))
                {
                    return true;
                }
                else
                {
                    url = GetDeltaCrlUrl(stCrlInfo);
                    if (!string.IsNullOrEmpty(url))
                    {
                        return IsCertificateInOnlineCRL(cert, url);
                    }
                }
            }
            finally
            {
                if (hCrlData.IsAllocated) hCrlData.Free();
                if (hCryptBlob.IsAllocated) hCryptBlob.Free();
                if (!pvContext.Equals(IntPtr.Zero))
                {
                    WinCrypt32.CertFreeCRLContext(pvContext);
                }
            }

            return false;
        }

        /// <summary>
        /// can be used to check if the certificate is available in a specific File for CRL.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="CRLFilePath"></param>
        /// <returns></returns>
        internal bool IsCertificateInCrlFile(X509Certificate2 cert, string CRLFilePath)
        {
            CRLData = File.ReadAllBytes(CRLFilePath);
            if (!CheckCRLMessageSignature(CRLData)) return false;

            IntPtr phCertStore = IntPtr.Zero;
            IntPtr pvContext = IntPtr.Zero;
            GCHandle hCrlData = new GCHandle();
            GCHandle hCryptBlob = new GCHandle();
            try
            {
                hCrlData = GCHandle.Alloc(CRLData, GCHandleType.Pinned);
                WinCrypt32.CRYPTOAPI_BLOB stCryptBlob;
                stCryptBlob.cbData = CRLData.Length;
                stCryptBlob.pbData = hCrlData.AddrOfPinnedObject();
                hCryptBlob = GCHandle.Alloc(stCryptBlob, GCHandleType.Pinned);

                if (!WinCrypt32.CryptQueryObject(
                WinCrypt32.CERT_QUERY_OBJECT_BLOB,
                hCryptBlob.AddrOfPinnedObject(),
                WinCrypt32.CERT_QUERY_CONTENT_FLAG_CRL,
                WinCrypt32.CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                ref phCertStore,
                IntPtr.Zero,
                ref pvContext
                ))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                WinCrypt32.CRL_CONTEXT stCrlContext = (WinCrypt32.CRL_CONTEXT)Marshal.PtrToStructure(pvContext, typeof(WinCrypt32.CRL_CONTEXT));
                WinCrypt32.CRL_INFO stCrlInfo = (WinCrypt32.CRL_INFO)Marshal.PtrToStructure(stCrlContext.pCrlInfo, typeof(WinCrypt32.CRL_INFO));

                CRLNextUpdate = WinCrypt32.FiletimeToDateTime(stCrlInfo.NextUpdate);
                if (CRLNextUpdate < DateTime.Now)
                {
                    throw new CRLExpection("CRL has expired");
                }

                if (IsCertificateInCrl(cert, stCrlInfo))
                {
                    return true;
                }
            }
            finally
            {
                if (hCrlData.IsAllocated) hCrlData.Free();
                if (hCryptBlob.IsAllocated) hCryptBlob.Free();
                if (!pvContext.Equals(IntPtr.Zero))
                {
                    WinCrypt32.CertFreeCRLContext(pvContext);
                }
            }

            return false;
        }

        /// <summary>
        /// Check the signature of the CRL Message
        /// </summary>
        /// <param name="CRLData">CRL as byte array</param>
        /// <returns>true in case of success</returns>
        /// <exception cref="CRLExpection">Returns this exception in case of failure</exception>
        private bool CheckCRLMessageSignature(byte[] CRLData)
        {
            GCHandle pCertContext = GCHandle.Alloc(IntPtr.Zero, GCHandleType.Pinned);

            //WinCrypt32.CRL_CONTEXT CrlCntxt = (WinCrypt32.CRL_CONTEXT)Marshal.PtrToStructure(CRLContext, typeof(WinCrypt32.CRL_CONTEXT));
            //WinCrypt32.CRL_INFO CrlInfo = (WinCrypt32.CRL_INFO)Marshal.PtrToStructure(CrlCntxt.pCrlInfo, typeof(WinCrypt32.CRL_INFO));
            try
            {
                IntPtr CRLContext = WinCrypt32.CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CRLData, CRLData.Length);

                if (IntPtr.Zero == CRLContext)
                {
                    throw new CRLExpection("Invalid CRL format");
                }
                //CRYPT_DATA_BLOB CRLBlob = new CRYPT_DATA_BLOB();
                //GCHandle pinnedArray = GCHandle.Alloc(CRLData, GCHandleType.Pinned);
                //CRLBlob.pbData = pinnedArray.AddrOfPinnedObject();
                //CRLBlob.cbData = CRLData.Length;
                WinCrypt32.CRYPT_VERIFY_MESSAGE_PARA VerifyParams = new WinCrypt32.CRYPT_VERIFY_MESSAGE_PARA();
                VerifyParams.cbSize = Marshal.SizeOf(VerifyParams);
                VerifyParams.dwMsgAndCertEncodingType = WinCrypt32.MY_TYPE;
                VerifyParams.hCryptProv = IntPtr.Zero;
                VerifyParams.pfnGetSignerCertificate = IntPtr.Zero;
                VerifyParams.pvGetArg = IntPtr.Zero;
                //int cbDecodedMessageBlob = 0;

                //#endif

                IntPtr IssuerCertContext = WinCrypt32.CertCreateCertificateContext(WinCrypt32.MY_TYPE, IssuerCertificate.RawData, IssuerCertificate.RawData.Length);
                bool result = WinCrypt32.CryptVerifyCertificateSignatureEx(IntPtr.Zero, WinCrypt32.MY_TYPE,
                    3, CRLContext, 2, IssuerCertContext, 1, IntPtr.Zero);

                //ref VerifyParams,      // Verify parameters.
                //0,              // Signer index.
                //CRLData,    // Pointer to signed BLOB.
                //CRLData.Length,    // Size of signed BLOB.
                //null,            // Buffer for decoded message.
                //ref cbDecodedMessageBlob,  // Size of buffer.
                //pCertContext.AddrOfPinnedObject()         // Pointer to signer certificate.
                //);
                /*if (!result)*/
                WinCrypt32.CertFreeCRLContext(CRLContext);
                WinCrypt32.CertFreeCertificateContext(IssuerCertContext);
                if (!result)
                {
                    throw new CRLExpection("CRL Signature Error - Error Number " + Marshal.GetLastWin32Error());
                }
                return result;
            }
            catch (CRLExpection e)
            {
                throw e;
            }
            catch
            {
                return false;
            }
            finally
            {
                pCertContext.Free();
            }
        }
    }
}
