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
        public enum GrantType
        {
            authorization_code,
            client_credentials,
            password
        }

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(Required = Required.Always, PropertyName = "grant_type")]
        public GrantType Type { get; set; } = GrantType.client_credentials;

        [JsonProperty(Required = Required.Default, PropertyName = "client_id")]
        public String ClientId { get; set; } = null;

        [JsonProperty(Required = Required.Default, PropertyName = "client_secret")]
        public String ClientSecret { get; set; } = null;

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
