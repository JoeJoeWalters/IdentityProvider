﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;

namespace Server.Contracts.Tokens
{
    /// <summary>
    /// Custom token request (e.g. via PIN from the Authorize endpoint) that usually is stored and a code reference returned
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
    public class CustomTokenRequest
    {
        [JsonProperty(Required = Required.Default, PropertyName = "type")]
        public String Type { get; set; } = CustomGrantTypes.Passcode;

        [JsonProperty(Required = Required.Default, PropertyName = "client_id")]
        public String Client_Id { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "username")]
        public String Username { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "passcode")]
        public List<KeyValuePair<int, string>> Passcode { get; set; } = new List<KeyValuePair<int, string>>();

        [JsonProperty(Required = Required.Default, PropertyName = "otp_identifier")]
        public String OTPIdentifier { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "otp")]
        public String OTP { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, PropertyName = "redirect_uri")]
        public String RedirectUri { get; set; } = String.Empty;
    }
}
