namespace Server.Authentication
{
    public class ServerSettings
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
    }
}
