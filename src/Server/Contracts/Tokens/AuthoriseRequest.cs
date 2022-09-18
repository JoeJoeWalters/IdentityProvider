using Newtonsoft.Json;

namespace IdentityProvider.Server.Contracts.Tokens;

/// <summary>
/// 
/// </summary>
[JsonObject]
public class AuthoriseRequest
{
    // Standard Properties

    /// <summary>
    /// Tells the authorization server which grant to execute
    /// code: authorization code
    /// token: access token
    /// id_token token: access token and id token
    /// </summary>
    public string response_type { get; set; } = "code";

    /// <summary>
    /// (Optional) How the result of the authorization request is formatted. Values:
    /// query: for Authorization Code grant. 302 Found triggers redirect.
    /// fragment: for Implicit grant. 302 Found triggers redirect.
    /// form_post: 200 OK with response parameters embedded in an HTML form as hidden parameters.
    /// web_message: For Silent Authentication.Uses HTML5 web messaging.
    /// </summary>
    public string response_mode { get; set; } = "query";

    /// <summary>
    /// The ID of the application that asks for authorization
    /// </summary>
    public string client_id { get; set; }

    /// <summary>
    /// Holds a URL. A successful response from this endpoint results in a redirect to this URL.
    /// </summary>
    public string redirect_uri { get; set; }

    /// <summary>
    /// A space-delimited list of permissions that the application requires
    /// </summary>
    public string scope { get; set; }

    /// <summary>
    /// An opaque value, used for security purposes. If this request parameter is set in the request, then it is returned to the application as part of the redirect_uri
    /// </summary>
    public string state { get; set; }

    // PKCE

    /// <summary>
    /// 
    /// </summary>
    public string code_challenge { get; set; }

    /// <summary>
    /// 
    /// </summary>
    public string code_challenge_method { get; set; }
}
