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
        // https://stackoverflow.com/questions/45876960/how-to-specify-audience-for-an-oauth2-access-token
        /// <summary>
        /// (Extended) Audience is not normally part of the auth request but indicates the partition key (e.g. logins for System A or System B)
        /// </summary>
        [JsonProperty(Required = Required.Always, PropertyName = "audience")]
        public String Audience { get; set; } = String.Empty;

        /// <summary>
        /// authorization_code, client_credentials, password, refresh_token
        /// </summary>
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

        /// <summary>
        /// Required when the grant_type is refresh_token
        /// </summary>
        [JsonProperty(Required = Required.Default, PropertyName = "refresh_token")]
        public String RefreshToken { get; set; } = String.Empty;

        /// <summary>
        /// How long the new token should be valid for in Seconds up to a Max of 2592000 (30 Days), default is 60 (1 minute)
        /// </summary>
        [JsonProperty(Required = Required.Default, PropertyName = "valid_for")]
        public Int32 ValidFor { get; set; } = 60; // In Seconds Max 2592000 (30 Days)

        [JsonProperty(Required = Required.Default, PropertyName = "code")]
        public String Code { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "redirect_uri")]
        public String RedirectUri { get; set; } = String.Empty;
    }
}
