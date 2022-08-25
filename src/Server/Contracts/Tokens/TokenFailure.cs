using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;

namespace IdentityProvider.Server.Contracts.Tokens
{
    /// <summary>
    /// On unsuccessful verification of a token request
    /// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
    public class TokenFailure
    {
        /// <summary>
        /// List of standard error reason types
        /// </summary>
        public enum ReasonType
        {
            invalid_request,
            invalid_client,
            invalid_grant,
            invalid_scope,
            unauthorized_client,
            unsupported_grant_type
        }

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(Required = Required.Always, PropertyName = "error")]
        public ReasonType Reason { get; set; }

        [JsonProperty(Required = Required.AllowNull, PropertyName = "error_description")]
        public String ReasonDescription { get; set; } = null;

        [JsonProperty(Required = Required.AllowNull, PropertyName = "error_uri")]
        public String ReasonUri { get; set; } = null;
    }
}
