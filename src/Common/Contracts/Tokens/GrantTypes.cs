namespace IdentityProvider.Common.Contracts.Tokens;

public class GrantTypes
{
    public const string AuthorisationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string Password = "password";
    public const string RefreshToken = "refresh_token";
}

public class CustomGrantTypes
{
    public const string Pin = "pin";
    public const string OTP = "otp";
}
