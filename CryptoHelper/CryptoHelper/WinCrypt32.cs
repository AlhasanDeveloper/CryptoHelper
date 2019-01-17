using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoHelper
{
    internal static class WinCrypt32
    {
        #region APIs

        //     BOOL WINAPI CertIsValidCRLForCertificate(
        //  _In_  PCCERT_CONTEXT pCert,
        //  _In_  PCCRL_CONTEXT pCRL,
        //  _In_  DWORD dwFlags,
        //  _In_  void *pvReserved
        //);
        [DllImport("CRYPT32.DLL", EntryPoint = "CertIsValidCRLForCertificate", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CertIsValidCRLForCertificate(IntPtr pCert, IntPtr pCrl, Int32 DWORD, IntPtr Reserver);

        [DllImport("CRYPT32.DLL", EntryPoint = "CryptQueryObject", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptQueryObject(
            Int32 dwObjectType,
            IntPtr pvObject,
            Int32 dwExpectedContentTypeFlags,
            Int32 dwExpectedFormatTypeFlags,
            Int32 dwFlags,
            IntPtr pdwMsgAndCertEncodingType,
            IntPtr pdwContentType,
            IntPtr pdwFormatType,
            ref IntPtr phCertStore,
            IntPtr phMsg,
            ref IntPtr ppvContext
            );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertFreeCRLContext", SetLastError = true)]
        public static extern Boolean CertFreeCRLContext(
            IntPtr pCrlContext
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertNameToStr", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 CertNameToStr(
            Int32 dwCertEncodingType,
            ref CRYPTOAPI_BLOB pName,
            Int32 dwStrType,
            StringBuilder psz,
            Int32 csz
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CertFindExtension", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertFindExtension(
            [MarshalAs(UnmanagedType.LPStr)]String pszObjId,
            Int32 cExtensions,
            IntPtr rgExtensions
        );

        [DllImport("CRYPT32.DLL", EntryPoint = "CryptFormatObject", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CryptFormatObject(
            Int32 dwCertEncodingType,
            Int32 dwFormatType,
            Int32 dwFormatStrType,
            IntPtr pFormatStruct,
            [MarshalAs(UnmanagedType.LPStr)]String lpszStructType,
            IntPtr pbEncoded,
            Int32 cbEncoded,
            StringBuilder pbFormat,
            ref Int32 pcbFormat
        );

        [DllImport("Crypt32.DLL", EntryPoint = "CertCreateCertificateContext",
           SetLastError = true,
           CharSet = CharSet.Unicode, ExactSpelling = false,
           CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr CertCreateCertificateContext(
         int dwCertEncodingType,
         byte[] pbCertEncoded,
         int cbCertEncoded);

        [DllImport("crypt32.dll")]
        public static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("Crypt32.DLL", EntryPoint = "CertCreateCRLContext",
           SetLastError = true,
           CharSet = CharSet.Unicode, ExactSpelling = false,
           CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr CertCreateCRLContext(
         int dwCertEncodingType,
         byte[] pbCertEncoded,
         int cbCertEncoded);

        #endregion APIs

        #region Structs

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_CONTEXT
        {
            public uint dwCertEncodingType;

            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
            public byte[] pbCertEncoded;

            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        // typedef struct _PUBLICKEYSTRUC
        // {
        //    BYTE bType;
        //    BYTE bVersion;
        //    WORD reserved;
        //    ALG_ID aiKeyAlg;
        // } BLOBHEADER, PUBLICKEYSTRUC;
        [StructLayout(LayoutKind.Sequential)]
        public struct PUBLICKEYSTRUC
        {
            public Byte bType;
            public Byte bVersion;
            public Int16 reserved;
            public Int32 aiKeyAlg;
        }

        // typedef struct _RSAPUBKEY
        // {
        //    DWORD magic;
        //    DWORD bitlen;
        //    DWORD pubexp;
        // } RSAPUBKEY;
        [StructLayout(LayoutKind.Sequential)]
        public struct RSAPUBKEY
        {
            public Int32 magic;
            public Int32 bitlen;
            public Int32 pubexp;
        }

        // typedef struct _CRYPTOAPI_BLOB
        // {
        //    DWORD   cbData;
        //    BYTE    *pbData;
        // } CRYPT_HASH_BLOB, CRYPT_INTEGER_BLOB,
        //   CRYPT_OBJID_BLOB, CERT_NAME_BLOB;
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTOAPI_BLOB
        {
            public Int32 cbData;
            public IntPtr pbData;
        }

        // typedef struct _CRYPT_ALGORITHM_IDENTIFIER
        // {
        //    LPSTR pszObjId;
        //    CRYPT_OBJID_BLOB Parameters;
        // } CRYPT_ALGORITHM_IDENTIFIER;
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public String pszObjId;

            public CRYPTOAPI_BLOB Parameters;
        }

        // typedef struct _CRYPT_SIGN_MESSAGE_PARA
        // {
        //    DWORD cbSize;
        //    DWORD dwMsgEncodingType;
        //    PCCERT_CONTEXT pSigningCert;
        //    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        //    void *pvHashAuxInfo;
        //    DWORD cMsgCert;
        //    PCCERT_CONTEXT *rgpMsgCert;
        //    DWORD cMsgCrl;
        //    PCCRL_CONTEXT *rgpMsgCrl;
        //    DWORD cAuthAttr;
        //    PCRYPT_ATTRIBUTE rgAuthAttr;
        //    DWORD cUnauthAttr;
        //    PCRYPT_ATTRIBUTE rgUnauthAttr;
        //    DWORD dwFlags;
        //    DWORD dwInnerContentType;
        // } CRYPT_SIGN_MESSAGE_PARA;
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_SIGN_MESSAGE_PARA
        {
            public Int32 cbSize;
            public Int32 dwMsgEncodingType;
            public IntPtr pSigningCert;
            public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            public IntPtr pvHashAuxInfo;
            public Int32 cMsgCert;
            public IntPtr rgpMsgCert;
            public Int32 cMsgCrl;
            public IntPtr rgpMsgCrl;
            public Int32 cAuthAttr;
            public IntPtr rgAuthAttr;
            public Int32 cUnauthAttr;
            public IntPtr rgUnauthAttr;
            public Int32 dwFlags;
            public Int32 dwInnerContentType;
        }

        // typedef struct _CRYPT_VERIFY_MESSAGE_PARA
        // {
        //    DWORD cbSize;
        //    DWORD dwMsgAndCertEncodingType;
        //    HCRYPTPROV hCryptProv;
        //    PFN_CRYPT_GET_SIGNER_CERTIFICATE pfnGetSignerCertificate;
        //    void *pvGetArg;
        // } CRYPT_VERIFY_MESSAGE_PARA;
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_VERIFY_MESSAGE_PARA
        {
            public Int32 cbSize;
            public Int32 dwMsgAndCertEncodingType;
            public IntPtr hCryptProv;
            public IntPtr pfnGetSignerCertificate;
            public IntPtr pvGetArg;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;

            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
            public byte[] pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct CERT_PUBLIC_KEY_INFO
        {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPTOAPI_BLOB PublicKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CERT_EXTENSION
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;

            public bool fCritical;
            public CRYPTOAPI_BLOB Value;
        }

        //[StructLayout(LayoutKind.Sequential)]
        //public struct CERT_CONTEXT
        //{
        //    public uint dwCertEncodingType;
        //    public IntPtr pbCertEncoded;
        //    public uint cbCertEncoded;
        //    public IntPtr pCertInfo;
        //    public IntPtr hCertStore;
        //}

        public struct CERT_INFO
        {
            public int dwVersion;
            public CRYPTOAPI_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public FILETIME NotBefore;
            public FILETIME NotAfter;
            public CRYPTOAPI_BLOB Subject;
            public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            public CRYPTOAPI_BLOB IssuerUniqueId;
            public CRYPTOAPI_BLOB SubjectUniqueId;
            public int cExtension;
            public CERT_EXTENSION rgExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_CONTEXT
        {
            public Int32 dwCertEncodingType;
            public IntPtr pbCrlEncoded;
            public Int32 cbCrlEncoded;
            public IntPtr pCrlInfo;
            public IntPtr hCertStore;
        }

        public static DateTime FiletimeToDateTime(FILETIME fileTime)
        {
            long hFT2 = (((long)fileTime.dwHighDateTime) << 32) | ((uint)fileTime.dwLowDateTime);
            return DateTime.FromFileTimeUtc(hFT2);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_INFO
        {
            public Int32 dwVersion;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public FILETIME ThisUpdate;
            public FILETIME NextUpdate;
            public Int32 cCRLEntry;
            public IntPtr rgCRLEntry;
            public Int32 cExtension;
            public IntPtr rgExtension;
        }

        // BOOL WINAPI CryptSignMessage(
        //    PCRYPT_SIGN_MESSAGE_PARA pSignPara,
        //    BOOL fDetachedSignature,
        //    DWORD cToBeSigned,
        //    const BYTE* rgpbToBeSigned[],
        //    DWORD rgcbToBeSigned[],
        //    BYTE* pbSignedBlob,
        //    DWORD* pcbSignedBlob
        // );
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern Boolean CryptSignMessage(
          ref CRYPT_SIGN_MESSAGE_PARA pSignPara,
          Boolean fDetachedSignature,
          Int32 cToBeSigned,
          IntPtr[] rgpbToBeSigned,
          Int32[] rgcbToBeSigned,
          Byte[] pbSignedBlob,
          ref Int32 pcbSignedBlob
        );

        //     BOOL WINAPI CryptVerifyCertificateSignatureEx(
        //  _In_         HCRYPTPROV_LEGACY hCryptProv,
        //  _In_         DWORD dwCertEncodingType,
        //  _In_         DWORD dwSubjectType,
        //  _In_         void *pvSubject,
        //  _In_         DWORD dwIssuerType,
        //  _In_         void *pvIssuer,
        //  _In_         DWORD dwFlags,
        //  _Inout_opt_  void *pvExtra
        //);
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern Boolean CryptVerifyCertificateSignatureEx(IntPtr Legacy,
            UInt32 EncodingType, UInt32 SubjectType, IntPtr Subject, UInt32 IssuerType, IntPtr Issuer, UInt32 Flags, IntPtr Extra);

        // BOOL WINAPI CryptVerifyMessageSignature(
        //    PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
        //    DWORD dwSignerIndex,
        //    const BYTE* pbSignedBlob,
        //    DWORD cbSignedBlob,
        //    BYTE* pbDecoded,
        //    DWORD* pcbDecoded,
        //    PCCERT_CONTEXT* ppSignerCert
        // );
        [DllImport("Crypt32.dll", SetLastError = true)]
        public static extern Boolean CryptVerifyMessageSignature(
          ref CRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
          Int32 dwSignerIndex,
          Byte[] pbSignedBlob,
          Int32 cbSignedBlob,
          Byte[] pbDecoded,
          ref Int32 pcbDecoded,
          IntPtr ppSignerCert
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public Int32 dwLowDateTime;
            public Int32 dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_ENTRY
        {
            public CRYPTOAPI_BLOB SerialNumber;
            public FILETIME RevocationDate;
            public Int32 cExtension;
            public IntPtr rgExtension;
        }

        #endregion Structs

        #region Consts

        // #define CERT_PERSONAL_STORE_NAME      L"My"
        public const string CERT_PERSONAL_STORE_NAME = "My";

        // #define CERT_COMPARE_NAME   2
        public const Int32 CERT_COMPARE_NAME = 2;

        // #define CERT_INFO_SUBJECT_FLAG  7
        public const Int32 CERT_INFO_SUBJECT_FLAG = 7;

        // #define CERT_COMPARE_SHIFT        16
        public const Int32 CERT_COMPARE_SHIFT = 16;

        // #define CERT_FIND_SUBJECT_NAME    (CERT_COMPARE_NAME << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG)
        public const Int32 CERT_FIND_SUBJECT_NAME =
          (CERT_COMPARE_NAME << CERT_COMPARE_SHIFT) | CERT_INFO_SUBJECT_FLAG;

        // #define CERT_COMPARE_NAME_STR_W     8
        public const Int32 CERT_COMPARE_NAME_STR_W = 8;

        // #define CERT_FIND_SUBJECT_STR_W     //   (CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG)
        public const Int32 CERT_FIND_SUBJECT_STR_W =
          (CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT) | CERT_INFO_SUBJECT_FLAG;

        // #define CERT_FIND_SUBJECT_STR CERT_FIND_SUBJECT_STR_W
        public const Int32 CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;

        // #define CERT_STORE_PROV_SYSTEM_W      ((LPCSTR) 10)
        public const Int32 CERT_STORE_PROV_SYSTEM_W = 10;

        // #define CERT_STORE_PROV_SYSTEM        CERT_STORE_PROV_SYSTEM_W
        public const Int32 CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W;

        // #define CERT_SYSTEM_STORE_CURRENT_USER_ID     1
        public const Int32 CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;

        // #define CERT_SYSTEM_STORE_LOCATION_SHIFT      16
        public const Int32 CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;

        // #define CERT_SYSTEM_STORE_CURRENT_USER          //   (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
        public const Int32 CERT_SYSTEM_STORE_CURRENT_USER =
          CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

        // #define CERT_CLOSE_STORE_CHECK_FLAG       0x00000002
        public const Int32 CERT_CLOSE_STORE_CHECK_FLAG = 0x00000002;

        // #define ALG_CLASS_HASH                  (4 << 13)
        // #define ALG_TYPE_ANY                    (0)
        // #define ALG_SID_SHA1                    4
        // #define CALG_SHA1               (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
        public const Int32 CALG_SHA1 = (4 << 13) | 4;

        // #define ALG_CLASS_SIGNATURE             (1 << 13)
        // #define ALG_TYPE_RSA                    (2 << 9)
        // #define ALG_SID_RSA_ANY                 0
        // #define CALG_RSA_SIGN           (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
        public const Int32 CALG_RSA_SIGN = (1 << 13) | (2 << 9);

        // #define PROV_RSA_FULL           1
        public const Int32 PROV_RSA_FULL = 0x00000001;

        // #define CRYPT_VERIFYCONTEXT     0xF0000000
        public const UInt32 CRYPT_VERIFYCONTEXT = 0xF0000000; //No private key access required

        // #define MY_TYPE       (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
        public const Int32 MY_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

        // #define HP_HASHVAL              0x0002
        public const Int32 HP_HASHVAL = 0x00000002;

        // #define HP_HASHSIZE             0x0004
        public const Int32 HP_HASHSIZE = 0x00000004;

        // #define PUBLICKEYBLOBEX 0xA
        public const Int32 PUBLICKEYBLOBEX = 0x0A;

        // #define PUBLICKEYBLOB           0x6
        public const Int32 PUBLICKEYBLOB = 0x06;

        // #define CUR_BLOB_VERSION 0x02
        public const Int32 CUR_BLOB_VERSION = 0x02;

        // #define CRYPT_EXPORTABLE        0x00000001
        public const Int32 CRYPT_EXPORTABLE = 0x00000001;

        // #define szOID_RSA_MD5           "1.2.840.113549.2.5"
        public const String szOID_RSA_MD5 = "1.2.840.113549.2.5";

        // #define szOID_RSA_MD5RSA        "1.2.840.113549.1.1.4"
        public const String szOID_RSA_MD5RSA = "1.2.840.113549.1.1.4";

        // #define szOID_OIWSEC_sha1       "1.3.14.3.2.26"
        public const String szOID_OIWSEC_sha1 = "1.3.14.3.2.26";

        public const Int32 CERT_QUERY_OBJECT_FILE = 0x00000001;
        public const Int32 CERT_QUERY_OBJECT_BLOB = 0x00000002;
        public const Int32 CERT_QUERY_CONTENT_CRL = 3;
        public const Int32 CERT_QUERY_CONTENT_FLAG_CRL = 1 << CERT_QUERY_CONTENT_CRL;
        public const Int32 CERT_QUERY_FORMAT_BINARY = 1;
        public const Int32 CERT_QUERY_FORMAT_BASE64_ENCODED = 2;
        public const Int32 CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;
        public const Int32 CERT_QUERY_FORMAT_FLAG_BINARY = 1 << CERT_QUERY_FORMAT_BINARY;
        public const Int32 CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = 1 << CERT_QUERY_FORMAT_BASE64_ENCODED;
        public const Int32 CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = 1 << CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED;
        public const Int32 CERT_QUERY_FORMAT_FLAG_ALL = CERT_QUERY_FORMAT_FLAG_BINARY | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED | CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED;

        public const Int32 X509_ASN_ENCODING = 0x00000001;
        public const Int32 PKCS_7_ASN_ENCODING = 0x00010000;

        public const Int32 X509_NAME = 7;

        public const Int32 CERT_SIMPLE_NAME_STR = 1;
        public const Int32 CERT_OID_NAME_STR = 2;
        public const Int32 CERT_X500_NAME_STR = 3;

        public const String szOID_CRL_REASON_CODE = "2.5.29.21";

        public enum Disposition : uint
        {
            CERT_STORE_ADD_NEW = 1,
            CERT_STORE_ADD_USE_EXISTING = 2,
            CERT_STORE_ADD_REPLACE_EXISTING = 3,
            CERT_STORE_ADD_ALWAYS = 4,
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
            CERT_STORE_ADD_NEWER = 6,
            CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7,
        }

        [Flags]
        public enum FindFlags : int
        {
            CRL_FIND_ISSUED_BY_AKI_FLAG = 0x1,
            CRL_FIND_ISSUED_BY_SIGNATURE_FLAG = 0x2,
            CRL_FIND_ISSUED_BY_DELTA_FLAG = 0x4,
            CRL_FIND_ISSUED_BY_BASE_FLAG = 0x8,
        }

        public enum FindType : int
        {
            CRL_FIND_ANY = 0,
            CRL_FIND_ISSUED_BY = 1,
            CRL_FIND_EXISTING = 2,
            CRL_FIND_ISSUED_FOR = 3
        }

        #endregion Consts
    }
}
