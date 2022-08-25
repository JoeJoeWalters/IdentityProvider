using Newtonsoft.Json;

namespace IdentityProvider.Server.Contracts.Tokens
{
    // https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
    /// <summary>
    /// 
    /// </summary>
    public class TokenIntrospectionRequest
    {
        /// <summary>
        /// The string value of the token.  For access tokens, this is the "access_token" value returned from the token endpoint defined in OAuth 2.0
        /// </summary>
        [JsonProperty(Required = Required.Always, PropertyName = "token")]
        public string token { get; set; } = String.Empty;

        /// <summary>
        /// A hint about the type of the token submitted for introspection
        /// </summary>
        [JsonProperty(Required = Required.Default, PropertyName = "token_type_hint")]
        public string token_type_hint { get; set; } = "jwt";
    }
}
