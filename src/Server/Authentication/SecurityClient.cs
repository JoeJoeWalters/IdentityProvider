using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityProvider.Server.Authentication;

/// <summary>
/// A user object specifically for defining the security context
/// of a potential user login
/// </summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore, MemberSerialization = MemberSerialization.OptOut)]
public class SecurityClient
{
    [JsonProperty(Required = Required.Always)]
    public String Id { get; set; }

    [JsonProperty(Required = Required.AllowNull)]
    public String Secret { get; set; } = String.Empty;

    [JsonProperty(Required = Required.Default)]
    public String Name { get; set; } = String.Empty;

    [JsonProperty("Claims", Required = Required.AllowNull)]
    public List<String> Claims { get; set; }

    [JsonProperty("Scopes", Required = Required.AllowNull)]
    public List<String> Scopes { get; set; }

    [JsonProperty("Created", Required = Required.Default)]
    public DateTime Created { get; set; }

    [JsonProperty("Expires", Required = Required.Default)]
    public DateTime Expires { get; set; }
}

