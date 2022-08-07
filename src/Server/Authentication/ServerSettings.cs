namespace Server.Authentication
{
    public class Audience
    {
        public string Name { get; set; }
        public Boolean Primary { get; set; }
    }

    public class ServerSettings
    {
        // Defaults
        public Int16 AccessTokenExpiry { get => 60; }
        public Int16 RefreshTokenExpiry { get => 3600; }

        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public int PasscodeSize { get; set; }
        public string Issuer { get; set; }
        public List<Audience> Audiences { get; set; }
    }
}
