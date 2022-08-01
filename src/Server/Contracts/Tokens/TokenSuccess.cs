using Newtonsoft.Json;
using System;

namespace Server.Contracts.Tokens
{
    /// <summary>
    /// On successful verification of a token request
    /// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
    public class TokenSuccess
    {
        [JsonProperty(Required = Required.Always, PropertyName = "access_token")]
        public String AccessToken { get; set; }

        [JsonProperty(Required = Required.Always, PropertyName = "token_type")]
        public String TokenType { get; set; } = "bearer";

        [JsonProperty(Required = Required.AllowNull, PropertyName = "expires_in")]
        public Int16 ExpiresIn { get; set; } = (Int16)3600;

        [JsonProperty(Required = Required.AllowNull, PropertyName = "refresh_token")]
        public String RefreshToken { get; set; } = null;

        [JsonProperty(Required = Required.AllowNull, PropertyName = "scope")]
        public String Scope { get; set; } = null;
    }

}
