namespace Server.Authentication
{
    public class Audience
    {
        public string Name { get; set; }
        public Boolean Primary { get; set; }
    }

    public class ServerSettings
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public string Issuer { get; set; }
        public List<Audience> Audiences { get; set; }
    }
}
