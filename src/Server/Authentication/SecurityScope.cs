using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityProvider.Server.Authentication;

/// <summary>
/// A scope object to define scopes that this service can accept and handle
/// </summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore, MemberSerialization = MemberSerialization.OptOut)]
public class SecurityScope
{
    [JsonProperty(Required = Required.Always)]
    public String Id { get; set; }

    [JsonProperty(Required = Required.Default)]
    public String Value { get; set; } = String.Empty;
}

