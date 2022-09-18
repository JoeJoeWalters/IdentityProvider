using Newtonsoft.Json;

namespace IdentityProvider.Server.Contracts.Tokens;

/// <summary>
/// 
/// </summary>
[JsonObject]
public class AuthoriseResponse
{
    /// <summary>
    /// The authorization code to be used by the calling service to get the token if "code" is used
    /// </summary>
    public string? code { get; set; }

    /// <summary>
    /// If an access token response is requested
    /// </summary>
    public string? access_token { get; set; }

    /// <summary>
    /// If a token is returned, what type is it?
    /// </summary>
    public string? token_type { get; set; }

    /// <summary>
    /// If an id token is requested
    /// </summary>
    public string? id_token { get; set; }

    /// <summary>
    /// Returning back the state value passed in the request
    /// </summary>
    public string? state { get; set; }
}
