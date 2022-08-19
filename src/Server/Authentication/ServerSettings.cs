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

        public string PublicKey { get; set; } = string.Empty;
        public string PrivateKey { get; set; } = string.Empty;
        public int PinSize { get; set; } = 6;
        public string Issuer { get; set; } = string.Empty;
        public List<Audience> Audiences { get; set; } = new List<Audience>() { };

        public SecurityData SecurityData { get; set; } = new SecurityData() { };
    }
}
