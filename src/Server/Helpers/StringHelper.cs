using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Server.Helpers
{
    public static class StringHelper
    {
        public static string PrettyJson(this string value)
            => value; //JValue.Parse(value).ToString(Formatting.Indented);
    }
}
