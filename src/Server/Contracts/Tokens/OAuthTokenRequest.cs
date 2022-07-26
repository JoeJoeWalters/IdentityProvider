using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;

namespace Server.Contracts.Tokens
{
    /// <summary>
    /// Request for a set of credentials (client id, secret etc.)
    /// to be validated to give back an access token
    /// https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
    /// https://www.oauth.com/oauth2-servers/access-tokens/password-grant/
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
    public class OAuthTokenRequest
    {
        [JsonProperty(Required = Required.Always, PropertyName = "grant_type")]
        public String Type { get; set; } = GrantTypes.ClientCredentials;

        [JsonProperty(Required = Required.Default, PropertyName = "client_id")]
        public String ClientId { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "client_secret")]
        public String ClientSecret { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "username")]
        public String Username { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "password")]
        public String Password { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "code")]
        public String Code { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "redirect_uri")]
        public String RedirectUri { get; set; } = String.Empty;
    }
}
