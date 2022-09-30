using IdentityProvider.Common.Contracts.Tokens;
using Newtonsoft.Json;

namespace IdentityProvider.Server.Contracts.Tokens;

/// <summary>
/// Custom token request (e.g. via PIN from the Authorize endpoint) that usually is stored and a code reference returned
/// </summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public class TokenRequest
{
    [JsonProperty(Required = Required.Default, PropertyName = "type")]
    public String Type { get; set; } = CustomGrantTypes.Pin;

    [JsonProperty(Required = Required.Default, PropertyName = "client_id")]
    public String Client_Id { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "client_secret")]
    public String Client_Secret { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "username")]
    public String Username { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "password")]
    public String Password { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "pin")]
    public List<KeyValuePair<int, string>> Pin { get; set; } = new List<KeyValuePair<int, string>>();

    [JsonProperty(Required = Required.Default, PropertyName = "otp_identifier")]
    public String OTPIdentifier { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "otp")]
    public String OTP { get; set; } = String.Empty;

    // PKCE

    [JsonProperty(Required = Required.AllowNull, PropertyName = "code_challenge")]
    public string? CodeChallenge { get; set; } = null;

    [JsonProperty(Required = Required.AllowNull, PropertyName = "code_challenge_method")]
    public string? CodeChallengeMethod { get; set; } = null;

    [JsonProperty(Required = Required.AllowNull, PropertyName = "code_verifier")]
    public string? CodeVerifier { get; set; } = null;

    /// <summary>
    /// How long the new token should be valid for in Seconds up to a Max of 2592000 (30 Days), default is 60 (1 minute)
    /// </summary>
    [JsonProperty(Required = Required.Default, PropertyName = "valid_for")]
    public Int32 ValidFor { get; set; } = 60; // In Seconds Max 2592000 (30 Days)

    /// <summary>
    /// Response method and data
    /// </summary>

    [JsonProperty(Required = Required.Default, PropertyName = "code")]
    public String Code { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default, PropertyName = "redirect_uri")]
    public String RedirectUri { get; set; } = String.Empty;

    /// <summary>
    /// Required when the grant_type is refresh_token
    /// </summary>
    [JsonProperty(Required = Required.Default, PropertyName = "refresh_token")]
    public String Refresh_Token { get; set; } = String.Empty;

    /// <summary>
    /// List of scopes for this request (either alredy defined when requesting vai a code or passed in here if e.g. client auth flow
    /// </summary>
    [JsonProperty(Required = Required.Default, PropertyName = "scope")]
    public String Scope { get; set; } = String.Empty;
}
