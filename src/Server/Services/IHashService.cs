namespace IdentityProvider.Server.Services
{
    /// <summary>
    /// Interface for the service to hash pins/passwords etc.
    /// </summary>
    public interface IHashService
    {
        /// <summary>
        /// Generate the hash for a given string
        /// </summary>
        /// <param name="value">The value to hash</param>
        /// <returns>The hash for the value</returns>
        string CreateHash(string value);

        /// <summary>
        /// Do the comparison to as hash inside the function rather than returning for caller to compare
        /// </summary>
        /// <param name="value">The string to compare</param>
        /// <param name="hash">The known hash</param>
        /// <returns>Does it match?</returns>
        Boolean Compare(string value, string hash);
    }
}
