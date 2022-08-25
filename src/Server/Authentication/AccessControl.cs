using Newtonsoft.Json;
using System.Collections.Generic;

namespace IdentityProvider.Server.Authentication
{
    /// <summary>
    /// Access control list that should contain the users that are validated against
    /// not always stored in a database as the users may contain keys that are generated 
    /// only whilst the session is alive etc.
    /// </summary>
    [JsonObject]
    public class AccessControl
    {
        [JsonProperty(Required = Required.Default)]
        public List<SecurityClient> Clients { get; set; }

        [JsonProperty(Required = Required.Default)]
        public List<SecurityData> Users { get; set; }
    }
}
