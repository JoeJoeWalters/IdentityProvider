using System.Security.Cryptography;
using System.Text;

namespace Server.Services
{
    /// <summary>
    /// Hash strings
    /// </summary>
    public class HashService : IHashService
    {
        /// <summary>
        /// Generate the hash for a given string
        /// </summary>
        /// <param name="value">The value to hash</param>
        /// <returns>The hash for the value</returns>
        public string CreateHash(string value) 
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in GetHash(value))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }

        /// <summary>
        /// Do the comparison to as hash inside the function rather than returning for caller to compare
        /// </summary>
        /// <param name="value">The string to compare</param>
        /// <param name="hash">The known hash</param>
        /// <returns>Does it match?</returns>
        public Boolean Compare(string value, string hash)
            => CreateHash(value) == hash;

        /// <summary>
        /// Generate the bytes for the hash
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private byte[] GetHash(string value)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
                return algorithm.ComputeHash(Encoding.UTF8.GetBytes(value));
        }
    }
}
