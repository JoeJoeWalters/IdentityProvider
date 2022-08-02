using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Web;

namespace Server.Helpers
{
    public static class StringHelper
    {
        public static string PrettyJson(this string value)
            => value; //JValue.Parse(value).ToString(Formatting.Indented);

        public static string ToQueryString<T>(this T value)
        {
            var properties = from p in value.GetType().GetProperties()
                             where p.GetValue(value, null) != null
                             select p.Name + "=" + HttpUtility.UrlEncode(p.GetValue(value, null).ToString());
                
            return String.Join("&", properties.ToArray());
        }
    }
}
