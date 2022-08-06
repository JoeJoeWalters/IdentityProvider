using Microsoft.IdentityModel.Tokens;

namespace Server.Services
{
    /// <summary>
    /// Interface for storing security tokens for later retrieval
    /// </summary>
    public interface ITokenStorage
    {
        /// <summary>
        /// Add a security token to the token storage in exchange for an identifier
        /// </summary>
        /// <param name="token">The security token to store</param>
        /// <returns>Identifier for the token</returns>
        string Add(SecurityToken token);

        /// <summary>
        /// Exchange an identifier for the security token
        /// </summary>
        /// <param name="id">The token identifier</param>
        /// <returns>The security token</returns>
        SecurityToken Retrieve(string id);
    }
}
