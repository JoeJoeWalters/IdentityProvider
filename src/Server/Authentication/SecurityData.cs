using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityProvider.Server.Authentication
{
    /// <summary>
    /// A user object specifically for defining the security context
    /// of a potential user login
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore, MemberSerialization = MemberSerialization.OptOut)]
    public class SecurityData
    {
        [JsonProperty(Required = Required.Always)]
        public String Id { get; set; }

        [JsonProperty(Required = Required.AllowNull)]
        public String Key { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public String ClientId { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Always)]
        public String Username { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public String Password { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public PinData Pin { get; set; } = new PinData() { };

        [JsonProperty(Required = Required.AllowNull)]
        public List<Claim> Claims { get; set; }

        [JsonProperty("Scopes", Required = Required.AllowNull)]
        public List<String> Scopes { get; set; }

        [JsonProperty("Created", Required = Required.Default)]
        public DateTime Created { get; set; }

        [JsonProperty("Expires", Required = Required.Default)]
        public DateTime Expires { get; set; }
    }

    /// <summary>
    /// Object for storing a pin number for the credentials
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore, MemberSerialization = MemberSerialization.OptOut)]
    public class PinData
    {
        /// <summary>
        /// The plain text version of the Pin
        /// </summary>
        [JsonProperty(Required = Required.AllowNull)]
        public String Value { get; set; } = String.Empty;

        /// <summary>
        /// An array of the digits in the Pin with a hash
        /// </summary>
        [JsonProperty("HashedDigits", Required = Required.AllowNull)]
        public List<String> HashedDigits { get; set; } = new List<string>();
    }
}
