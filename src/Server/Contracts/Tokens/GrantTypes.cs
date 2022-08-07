namespace Server.Contracts.Tokens
{
    public class GrantTypes
    {
        public const string AuthorisationCode = "authorization_code";
        public const string ClientCredentials = "client_credentials";
        public const string Password = "password";
        public const string RefreshToken = "refresh_token";
    }

    public class CustomGrantTypes
    {
        public const string Passcode = "passcode";
        public const string OTP = "otp";
    }
}
