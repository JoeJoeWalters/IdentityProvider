using System.Security.Cryptography;
using System.Text;

namespace IdentityProvider.Server.Helpers;

public static class KeyHelper
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static string ComputeSha1Hash(this string value)
    {
        // Create a SHA256   
        using (SHA1 shaHash = SHA1.Create())
        {
            // ComputeHash - returns byte array  
            byte[] bytes = shaHash.ComputeHash(Encoding.UTF8.GetBytes(value));

            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static string StripPEM(this string value)
        => value.Replace("\r", String.Empty)
            .Replace("\n", String.Empty)
            .Replace("-----BEGIN PUBLIC KEY-----", String.Empty)
            .Replace("-----END PUBLIC KEY-----", String.Empty);
}
