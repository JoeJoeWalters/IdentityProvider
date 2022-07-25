using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Server.Authentication
{
    /// <summary>
    /// A user object specifically for defining the security context
    /// of a potential user login
    /// </summary>
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore, MemberSerialization = MemberSerialization.OptOut)]
    public class SecurityUser
    {
        public enum AuthenticationType
        {
            basic,
            oauth,
            apikey
        }

        [JsonProperty(Required = Required.Always)]
        public String Id { get; set; }

        [JsonProperty(Required = Required.AllowNull)]
        public String Key { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public String ClientId { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public String ClientSecret { get; set; } = String.Empty;

        [JsonProperty("Authentication", ItemConverterType = typeof(StringEnumConverter))]
        public List<AuthenticationType> Authentication { get; set; }

        [JsonProperty(Required = Required.Always)]
        public String Username { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default)]
        public String Password { get; set; } = String.Empty;

        [JsonProperty(Required = Required.Default, ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore, ItemConverterType = typeof(ClaimConverter))]
        public List<Claim> Claims { get; set; }
    }

    /// <summary>
    /// Custom converter for serialising and deserialising claims
    /// </summary>
    public class ClaimConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return (objectType == typeof(Claim));
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject jo = JObject.Load(reader);
            string type = (string)jo["Type"];
            string value = (string)jo["Value"];
            string valueType = (string)jo["ValueType"];
            string issuer = (string)jo["Issuer"];
            string originalIssuer = (string)jo["OriginalIssuer"];
            return new Claim(type, value, valueType, issuer, originalIssuer);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var claim = (Claim)value;
            JObject jo = new JObject();
            jo.Add("Type", claim.Type);
            jo.Add("Value", IsJson(claim.Value) ? new JRaw(claim.Value) : new JValue(claim.Value));
            jo.Add("ValueType", claim.ValueType);
            jo.Add("Issuer", claim.Issuer);
            jo.Add("OriginalIssuer", claim.OriginalIssuer);
            jo.WriteTo(writer);
        }

        private bool IsJson(string val)
        {
            return (val != null &&
                    (val.StartsWith("[") && val.EndsWith("]")) ||
                    (val.StartsWith("{") && val.EndsWith("}")));
        }

        public override bool CanWrite
        {
            get { return true; }
        }
    }
}
