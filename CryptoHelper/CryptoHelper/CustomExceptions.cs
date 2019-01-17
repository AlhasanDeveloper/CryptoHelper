using System;

namespace CryptoHelper
{
    /// <summary>
    /// The handler for OCSP exceptions
    /// </summary>
    public class OCSPExpection : Exception
    {
        public OCSPExpection(string message) : base(message)
        {
        }

        public OCSPExpection(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// The handler for CRL exceptions
    /// </summary>
    public class CRLExpection : Exception
    {
        public CRLExpection(string message) : base(message)
        {
        }

        public CRLExpection(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
