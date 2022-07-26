namespace Server.Helpers
{
    public static class HttpHelper
    {
        public static string GetBaseUri(this HttpContext context)
            => $"{(context.Request.IsHttps ? "https" : "http")}://{context.Request.Host.Value}/";
    }
}
