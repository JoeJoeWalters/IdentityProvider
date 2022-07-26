namespace Server.Contracts.MetaData
{
    //https://auth0.com/blog/navigating-rs256-and-jwks/
    public class JWKS
    {
        /// <summary>
        /// List of available keys for use with the identity provider
        /// </summary>
        public List<JWKSKey> Keys { get; set; }
    }

    public class JWKSKey
    {
        /// <summary>
        /// algorithm for the key
        /// </summary>
        public string alg { get; set; } = String.Empty;

        /// <summary>
        ///  key type
        /// </summary>
        public string kty { get; set; } = String.Empty;

        /// <summary>
        /// how the key was meant to be used. e.g. sig represents signature verification.
        /// </summary>
        public string use { get; set; } = "sig";

        /// <summary>
        /// is the x509 certificate chain
        /// </summary>
        public string x5c { get; set; } = String.Empty;

        /// <summary>
        /// moduluos for a standard pem
        /// </summary>
        public string n { get; set; } = String.Empty;

        /// <summary>
        /// exponent for a standard pem
        /// </summary>
        public string e { get; set; } = String.Empty;

        /// <summary>
        /// unique identifier for the key
        /// </summary>
        public string kid { get; set; } = String.Empty;

        /// <summary>
        /// thumbprint of the x.509 cert (SHA-1 thumbprint)
        /// </summary>
        public string x5t { get; set; } = String.Empty;
    }
}
