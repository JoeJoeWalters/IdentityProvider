using Newtonsoft.Json;

namespace IdentityProvider.Server.Contracts.Tokens;

// https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
// https://www.oauth.com/oauth2-servers/token-introspection-endpoint/
/// <summary>
/// 
/// </summary>
public class TokenIntrospectionResponse
{
    /// <summary>
    /// Is the token active
    /// </summary>
    [JsonProperty(Required = Required.Always, PropertyName = "active")]
    public Boolean active { get; set; } = false;

    /// <summary>
    /// A JSON string containing a space-separated list of scopes associated with this token
    /// </summary>
    [JsonProperty(Required = Required.AllowNull, PropertyName = "scope")]
    public string? scope { get; set; }

    /// <summary>
    /// The client identifier for the OAuth 2.0 client that the token was issued to.
    /// </summary>
    [JsonProperty(Required = Required.AllowNull, PropertyName = "client_id")]
    public string? client_id { get; set; }

    /// <summary>
    /// A human-readable identifier for the user who authorized this token.
    /// </summary>
    [JsonProperty(Required = Required.AllowNull, PropertyName = "username")]
    public string? username { get; set; }

    /// <summary>
    /// The unix timestamp (integer timestamp, number of seconds since January 1, 1970 UTC) indicating when this token will expire.
    /// </summary>
    [JsonProperty(Required = Required.AllowNull, PropertyName = "exp")]
    public int? exp { get; set; }
}
